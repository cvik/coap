const std = @import("std");
const coap = @import("coap");
const coapz = @import("coapz");
const protocol = @import("protocol.zig");
pub const Session = struct {
    client: coap.Client,
    nonce: [16]u8,
    expected: u32,
    active: bool = true,

    pub fn open(allocator: std.mem.Allocator, host: []const u8, port: u16, psk: ?coap.Psk, count: u32, mode: protocol.Mode) !?Session {
        if (count == 0 or count > protocol.max_requests) return error.BenchmarkCapacityExceeded;
        var session: Session = .{ .client = try coap.Client.init(allocator, .{ .host = host, .port = port, .psk = psk, .max_in_flight = 1, .handshake_timeout_ms = 5000 }), .nonce = undefined, .expected = count, .active = false };
        errdefer session.deinit();
        if (psk != null) try session.client.handshake();
        const info = session.request(.get, "/__bench/v1/info", &.{}) catch |err| {
            // Preserve CON against generic echo servers. NON must never fall
            // back to sent/sec when remote receipts are unavailable.
            if (mode == .con and err == error.NotBenchmarkServer) {
                session.client.deinit();
                return null;
            }
            return err;
        };
        if (info.capacity == 0 or info.capacity > protocol.max_requests) return error.InvalidBenchmarkStats;
        if (count > info.capacity) return error.BenchmarkCapacityExceeded;
        coap.platform.randomBytes(&session.nonce);
        const start: protocol.Start = .{ .nonce = session.nonce, .expected = count, .mode = mode };
        const bytes = start.encode();
        const initial = try session.request(.post, "/__bench/v1/start", &bytes);
        session.active = true;
        _ = try session.validate(initial);
        if (initial.received != 0 or initial.duplicates != 0) return error.InvalidBenchmarkStats;
        return session;
    }
    pub fn prefix(self: *const Session) [4]u8 {
        return self.nonce[0..4].*;
    }
    pub fn deinit(self: *Session) void {
        if (self.active) _ = self.finish() catch |err| {
            std.debug.print("warning: remote finish failed ({s}); server lease will expire\n", .{@errorName(err)});
        };
        self.client.deinit();
        std.crypto.secureZero(u8, &self.nonce);
    }
    fn request(self: *Session, code: coapz.Code, path: []const u8, body: []const u8) !protocol.Stats {
        return self.requestUntil(code, path, body, coap.platform.nanoTimestamp() + 5 * std.time.ns_per_s);
    }
    fn requestUntil(self: *Session, code: coapz.Code, path: []const u8, body: []const u8, deadline: i128) !protocol.Stats {
        var storage: coap.Client.ResponseStorage(0) = .{};
        var options: [coap.uri.max_options]coapz.Option = undefined;
        const handle = try self.client.submit(storage.buffers(), code, coap.uri.fromUri(path, &options), body);
        var completed = false;
        defer if (!completed) self.client.cancel(handle);
        while (coap.platform.nanoTimestamp() < deadline) {
            const completion = (try self.client.poll(50)) orelse continue;
            if (completion.handle != handle) return error.UnexpectedControlCompletion;
            completed = true;
            const result = try completion.result;
            switch (result.code) {
                .content => return protocol.Stats.decode(result.payload),
                .not_found, .method_not_allowed => return error.NotBenchmarkServer,
                .service_unavailable => return error.BenchmarkBusy,
                .request_entity_too_large => return error.BenchmarkCapacityExceeded,
                .request_entity_incomplete => return error.BenchmarkSessionExpired,
                .forbidden => return error.BenchmarkOwnerMismatch,
                else => return error.BenchmarkControlRejected,
            }
        }
        return error.BenchmarkControlTimeout;
    }
    pub fn stats(self: *Session) !protocol.Stats {
        const value = try self.request(.post, "/__bench/v1/stats", &self.nonce);
        return self.validate(value);
    }
    fn validate(self: *const Session, value: protocol.Stats) !protocol.Stats {
        if (!value.active or value.expected != self.expected or value.received > self.expected or value.capacity < self.expected or value.capacity > protocol.max_requests or value.tracking_failed) return error.InvalidBenchmarkStats;
        return value;
    }
    pub fn drain(self: *Session) !protocol.Stats {
        const deadline = coap.platform.nanoTimestamp() + 5 * std.time.ns_per_s;
        while (true) {
            const value = try self.validate(try self.requestUntil(.post, "/__bench/v1/stats", &self.nonce, deadline));
            if (value.received == self.expected or value.idle_ns >= 250 * std.time.ns_per_ms) return value;
            if (coap.platform.nanoTimestamp() >= deadline) return error.BenchmarkDrainTimeout;
            coap.platform.sleep(25 * std.time.ns_per_ms);
        }
    }
    pub fn finish(self: *Session) !protocol.Stats {
        const value = try self.request(.post, "/__bench/v1/finish", &self.nonce);
        if (!value.active) self.active = false;
        if (value.active or value.expected != self.expected or value.received > self.expected or value.capacity < self.expected or value.capacity > protocol.max_requests or value.tracking_failed) return error.InvalidBenchmarkStats;
        return value;
    }
};
