//! Caller-bounded benchmark state. Only initialization allocates.
//! Per-worker locks avoid a globally contended reader counter on the data path.
const std = @import("std");
const coap = @import("coap");
const protocol = @import("protocol.zig");
const Atomic = std.atomic.Value;
const Row = struct {
    mutex: std.Io.Mutex align(std.atomic.cache_line) = .init,
    unique: u64 = 0,
    duplicates: u64 = 0,
    first: u64 = 0,
    last: u64 = 0,
    // Only this row's worker writes replies. Serialization finishes before its
    // next callback; other workers/control operations never overwrite replies.
    reply: [protocol.stats_len]u8 = undefined,
};
var next_context_id: Atomic(u64) = .init(1);
threadlocal var cached_context: u64 = 0;
threadlocal var cached_row: usize = 0;

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    rows: []Row,
    seen: []Atomic(u64),
    capacity: u32,
    timeout_ns: u64,
    context_id: u64,
    used: Atomic(usize) = .init(0),
    tracking_failed: Atomic(bool) = .init(false),
    control: std.Io.Mutex = .init,
    active: bool = false,
    nonce: [16]u8 = @splat(0),
    expected: u32 = 0,
    mode: protocol.Mode = .non,
    owner: std.Io.net.IpAddress = coap.platform.ip4(.{ 127, 0, 0, 1 }, 0),
    started: u64 = 0,
    touched: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: u32, row_count: usize, timeout_ms: u32, io: std.Io) !Context {
        if (capacity == 0 or capacity > protocol.max_requests or row_count == 0 or timeout_ms < 1000) return error.InvalidCapacity;
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        for (rows) |*entry| entry.* = .{};
        const seen = try allocator.alloc(Atomic(u64), (@as(usize, capacity) + 63) / 64);
        for (seen) |*word| word.* = .init(0);
        return .{ .allocator = allocator, .io = io, .rows = rows, .seen = seen, .capacity = capacity, .timeout_ns = @as(u64, timeout_ms) * std.time.ns_per_ms, .context_id = next_context_id.fetchAdd(1, .monotonic) };
    }
    pub fn deinit(self: *Context) void {
        std.crypto.secureZero(u8, &self.nonce);
        self.allocator.free(self.seen);
        self.allocator.free(self.rows);
    }
    fn row(self: *Context) ?*Row {
        if (cached_context != self.context_id) {
            cached_row = self.used.fetchAdd(1, .monotonic);
            cached_context = self.context_id;
        }
        if (cached_row >= self.rows.len) {
            self.tracking_failed.store(true, .release);
            return null;
        }
        return &self.rows[cached_row];
    }
    fn freeze(self: *Context) void {
        for (self.rows) |*r| r.mutex.lockUncancelable(self.io);
    }
    fn thaw(self: *Context) void {
        var i = self.rows.len;
        while (i > 0) {
            i -= 1;
            self.rows[i].mutex.unlock(self.io);
        }
    }
    fn snapshot(self: *Context, timestamp: u64) protocol.Stats {
        var stats: protocol.Stats = .{ .capacity = self.capacity, .expected = self.expected, .active = self.active, .tracking_failed = self.tracking_failed.load(.acquire) };
        var first: u64 = 0;
        var last: u64 = 0;
        for (self.rows) |r| {
            stats.received += r.unique;
            stats.duplicates += r.duplicates;
            if (r.first != 0 and (first == 0 or r.first < first)) first = r.first;
            last = @max(last, r.last);
        }
        stats.elapsed_ns = if (first == 0) 0 else last -| first;
        stats.idle_ns = timestamp -| @max(last, self.started);
        return stats;
    }
    fn expired(self: *Context, timestamp: u64) bool {
        var activity = @max(self.started, self.touched);
        for (self.rows) |r| activity = @max(activity, r.last);
        return timestamp -| activity >= self.timeout_ns;
    }
    fn sameHost(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
        var x = a;
        var y = b;
        switch (x) {
            .ip4 => |*v| v.port = 0,
            .ip6 => |*v| v.port = 0,
        }
        switch (y) {
            .ip4 => |*v| v.port = 0,
            .ip6 => |*v| v.port = 0,
        }
        return coap.platform.addressEqual(x, y);
    }
    fn authenticated(self: *Context, peer: std.Io.net.IpAddress, payload: []const u8) bool {
        return payload.len == 16 and std.mem.eql(u8, payload, &self.nonce) and coap.platform.addressEqual(peer, self.owner);
    }
    fn response(r: *Row, stats: protocol.Stats) coap.Response {
        r.reply = stats.encode();
        return coap.Response.ok(&r.reply);
    }
    pub fn handle(self: *Context, request: coap.Request) ?coap.Response {
        return self.handleAt(request, @intCast(coap.platform.nanoTimestamp()));
    }
    fn handleAt(self: *Context, request: coap.Request, timestamp: u64) ?coap.Response {
        const r = self.row() orelse return coap.Response.withCode(.service_unavailable);
        var path = request.pathSegments();
        if (path.next()) |part| {
            if (std.mem.eql(u8, part.value, "__bench")) {
                const v = path.next() orelse return coap.Response.notFound();
                const action = path.next() orelse return coap.Response.notFound();
                if (!std.mem.eql(u8, v.value, "v1") or path.next() != null) return coap.Response.notFound();
                if (request.packet.kind != .confirmable) return coap.Response.badRequest();
                self.control.lockUncancelable(self.io);
                defer self.control.unlock(self.io);
                self.freeze();
                defer self.thaw();
                if (std.mem.eql(u8, action.value, "info")) {
                    if (request.method() != .get or request.payload().len != 0) return coap.Response.badRequest();
                    return response(r, .{ .capacity = self.capacity, .active = self.active });
                }
                if (request.method() != .post) return coap.Response.methodNotAllowed();
                if (std.mem.eql(u8, action.value, "start")) {
                    const start = protocol.Start.decode(request.payload()) catch return coap.Response.badRequest();
                    if (start.expected > self.capacity) return coap.Response.withCode(.request_entity_too_large);
                    if (self.active and !self.expired(timestamp)) {
                        if (!coap.platform.addressEqual(request.peer_address, self.owner) or !std.mem.eql(u8, &start.nonce, &self.nonce)) return coap.Response.withCode(.service_unavailable);
                        if (start.expected != self.expected or start.mode != self.mode) return coap.Response.badRequest();
                        self.touched = timestamp;
                        return response(r, self.snapshot(timestamp));
                    }
                    self.active = true;
                    self.nonce = start.nonce;
                    self.expected = start.expected;
                    self.mode = start.mode;
                    self.owner = request.peer_address;
                    self.started = timestamp;
                    self.touched = timestamp;
                    self.tracking_failed.store(self.used.load(.acquire) > self.rows.len, .release);
                    for (self.seen) |*word| word.store(0, .monotonic);
                    for (self.rows) |*entry| {
                        entry.unique = 0;
                        entry.duplicates = 0;
                        entry.first = 0;
                        entry.last = 0;
                    }
                    return response(r, self.snapshot(timestamp));
                }
                if (!self.authenticated(request.peer_address, request.payload())) return coap.Response.withCode(.forbidden);
                if (self.active and self.expired(timestamp)) {
                    self.active = false;
                    return coap.Response.withCode(.request_entity_incomplete);
                }
                if (std.mem.eql(u8, action.value, "stats")) {
                    if (!self.active) return coap.Response.withCode(.request_entity_incomplete);
                    self.touched = timestamp;
                    return response(r, self.snapshot(timestamp));
                }
                if (std.mem.eql(u8, action.value, "finish")) {
                    self.active = false;
                    return response(r, self.snapshot(timestamp));
                }
                return coap.Response.notFound();
            }
        }
        r.mutex.lockUncancelable(self.io);
        defer r.mutex.unlock(self.io);
        if (!self.active or !sameHost(request.peer_address, self.owner)) return coap.Response.ok(request.payload());
        if (self.mode == .con) {
            if (request.packet.kind == .confirmable) r.last = timestamp;
        } else if (request.packet.kind == .non_confirmable) {
            const token = request.packet.token;
            if (token.len != 8 or !std.mem.eql(u8, token[0..4], self.nonce[0..4])) return coap.Response.ok(request.payload());
            const id = std.mem.readInt(u32, token[4..8], .big);
            if (id >= self.expected) return coap.Response.ok(request.payload());
            const mask = @as(u64, 1) << @as(u6, @truncate(id));
            if (self.seen[id / 64].fetchOr(mask, .monotonic) & mask == 0) r.unique += 1 else r.duplicates += 1;
            if (r.first == 0) r.first = timestamp;
            r.last = timestamp;
        }
        return coap.Response.ok(request.payload());
    }
};

const coapz = @import("coapz");
const test_owner = coap.platform.ip4(.{ 127, 0, 0, 1 }, 34000);
fn controlRequest(ctx: *Context, action: []const u8, body: []const u8, peer: std.Io.net.IpAddress, time: u64) coap.Response {
    const options = [_]coapz.Option{ .{ .kind = .uri_path, .value = "__bench" }, .{ .kind = .uri_path, .value = "v1" }, .{ .kind = .uri_path, .value = action } };
    return ctx.handleAt(.{ .packet = .{ .kind = .confirmable, .code = .post, .msg_id = 1, .token = "aa", .options = &options, .payload = body, .data_buf = &.{} }, .peer_address = peer, .arena = std.testing.failing_allocator }, time).?;
}
fn beginTest(ctx: *Context, nonce: [16]u8, count: u32, peer: std.Io.net.IpAddress, time: u64) !protocol.Stats {
    const start: protocol.Start = .{ .nonce = nonce, .expected = count, .mode = .non };
    const body = start.encode();
    const response = controlRequest(ctx, "start", &body, peer, time);
    try std.testing.expectEqual(coapz.Code.content, response.code);
    return protocol.Stats.decode(response.payload);
}
fn dataRequest(ctx: *Context, nonce: [16]u8, id: u32, peer: std.Io.net.IpAddress, time: u64) void {
    const token = protocol.token(nonce[0..4].*, id);
    _ = ctx.handleAt(.{ .packet = .{ .kind = .non_confirmable, .code = .get, .msg_id = @truncate(id), .token = &token, .options = &.{}, .payload = "data", .data_buf = &.{} }, .peer_address = peer, .arena = std.testing.failing_allocator }, time);
}
fn readTest(ctx: *Context, nonce: [16]u8, time: u64) !protocol.Stats {
    const response = controlRequest(ctx, "stats", &nonce, test_owner, time);
    try std.testing.expectEqual(coapz.Code.content, response.code);
    return protocol.Stats.decode(response.payload);
}
test "measurement isolates owner, phase, duplicates and late runs without request allocation" {
    var ctx = try Context.init(std.testing.allocator, 100, 4, 1000, std.testing.io);
    defer ctx.deinit();
    const nonce: [16]u8 = @splat(7);
    _ = try beginTest(&ctx, nonce, 5, test_owner, 100);
    dataRequest(&ctx, nonce, 0, test_owner, 200);
    dataRequest(&ctx, nonce, 4, coap.platform.ip4(.{ 127, 0, 0, 1 }, 34001), 300);
    dataRequest(&ctx, nonce, 4, test_owner, 400);
    dataRequest(&ctx, nonce, 5, test_owner, 500); // out of range
    dataRequest(&ctx, @splat(8), 1, test_owner, 600); // different run
    dataRequest(&ctx, nonce, 2, coap.platform.ip4(.{ 127, 0, 0, 2 }, 34000), 700); // different host
    var stats = try readTest(&ctx, nonce, 800);
    try std.testing.expectEqual(@as(u64, 2), stats.received);
    try std.testing.expectEqual(@as(u64, 1), stats.duplicates);
    try std.testing.expectEqual(@as(u64, 200), stats.elapsed_ns);
    // Retrying start is idempotent, not a counter reset.
    stats = try beginTest(&ctx, nonce, 5, test_owner, 900);
    try std.testing.expectEqual(@as(u64, 2), stats.received);
    const start: protocol.Start = .{ .nonce = @splat(9), .expected = 5, .mode = .non };
    const body = start.encode();
    try std.testing.expectEqual(coapz.Code.service_unavailable, controlRequest(&ctx, "start", &body, test_owner, 950).code);
    try std.testing.expectEqual(coapz.Code.forbidden, controlRequest(&ctx, "stats", &nonce, coap.platform.ip4(.{ 127, 0, 0, 1 }, 34001), 960).code);
    try std.testing.expectEqual(coapz.Code.forbidden, controlRequest(&ctx, "stats", &start.nonce, test_owner, 970).code);
    var finish = controlRequest(&ctx, "finish", &nonce, test_owner, 1000);
    try std.testing.expect(!(try protocol.Stats.decode(finish.payload)).active);
    dataRequest(&ctx, nonce, 1, test_owner, 1100);
    finish = controlRequest(&ctx, "finish", &nonce, test_owner, 1200);
    try std.testing.expectEqual(@as(u64, 2), (try protocol.Stats.decode(finish.payload)).received);
    _ = try beginTest(&ctx, @splat(9), 5, test_owner, 1300);
    dataRequest(&ctx, nonce, 0, test_owner, 1400);
    stats = try readTest(&ctx, @splat(9), 1500);
    try std.testing.expectEqual(@as(u64, 0), stats.received);
}
test "measurement lease recovers after crash and valid data refreshes activity" {
    var ctx = try Context.init(std.testing.allocator, 8, 4, 1000, std.testing.io);
    defer ctx.deinit();
    const nonce: [16]u8 = @splat(1);
    _ = try beginTest(&ctx, nonce, 8, test_owner, 1);
    dataRequest(&ctx, nonce, 1, test_owner, 900_000_000);
    const start: protocol.Start = .{ .nonce = @splat(2), .expected = 8, .mode = .non };
    const body = start.encode();
    const other = coap.platform.ip4(.{ 127, 0, 0, 2 }, 34000);
    try std.testing.expectEqual(coapz.Code.service_unavailable, controlRequest(&ctx, "start", &body, other, 1_400_000_000).code);
    _ = try beginTest(&ctx, start.nonce, 8, other, 2_100_000_000);
    try std.testing.expectEqual(coapz.Code.forbidden, controlRequest(&ctx, "stats", &nonce, test_owner, 2_100_000_001).code);
    try std.testing.expectEqual(coapz.Code.request_entity_incomplete, controlRequest(&ctx, "stats", &start.nonce, other, 3_200_000_000).code);
}
test "measurement capacity and control methods reject without changing session" {
    var ctx = try Context.init(std.testing.allocator, 8, 2, 1000, std.testing.io);
    defer ctx.deinit();
    const start: protocol.Start = .{ .nonce = @splat(1), .expected = 9, .mode = .non };
    const body = start.encode();
    try std.testing.expectEqual(coapz.Code.request_entity_too_large, controlRequest(&ctx, "start", &body, test_owner, 1).code);
    try std.testing.expect(!ctx.active);
    try std.testing.expectEqual(coapz.Code.bad_request, controlRequest(&ctx, "start", &.{}, test_owner, 2).code);
    const options = [_]coapz.Option{ .{ .kind = .uri_path, .value = "__bench" }, .{ .kind = .uri_path, .value = "v1" }, .{ .kind = .uri_path, .value = "start" } };
    const response = ctx.handleAt(.{ .packet = .{ .kind = .non_confirmable, .code = .post, .msg_id = 1, .token = "aa", .options = &options, .payload = &body, .data_buf = &.{} }, .peer_address = test_owner, .arena = std.testing.failing_allocator }, 3).?;
    try std.testing.expectEqual(coapz.Code.bad_request, response.code);
    try std.testing.expect(!ctx.active);
}
fn concurrentData(ctx: *Context, index: u32) void {
    const nonce: [16]u8 = @splat(3);
    for (0..500) |i| dataRequest(ctx, nonce, index * 500 + @as(u32, @intCast(i)), test_owner, 1000 + i);
    dataRequest(ctx, nonce, 2000, test_owner, 2000);
}
test "measurement concurrent workers deduplicate globally with stable control snapshots" {
    var ctx = try Context.init(std.testing.allocator, 2001, 8, 1000, std.testing.io);
    defer ctx.deinit();
    const nonce: [16]u8 = @splat(3);
    _ = try beginTest(&ctx, nonce, 2001, test_owner, 1);
    var threads: [4]std.Thread = undefined;
    var spawned: usize = 0;
    defer for (threads[0..spawned]) |thread| thread.join();
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, concurrentData, .{ &ctx, @as(u32, @intCast(i)) });
        spawned += 1;
    }
    for (0..20) |_| {
        const snapshot = try readTest(&ctx, nonce, 2100);
        try std.testing.expect(snapshot.received <= 2001);
    }
    for (threads) |thread| thread.join();
    spawned = 0;
    const stats = try readTest(&ctx, nonce, 2200);
    try std.testing.expectEqual(@as(u64, 2001), stats.received);
    try std.testing.expectEqual(@as(u64, 3), stats.duplicates);
    try std.testing.expect(!stats.tracking_failed);
}
test "measurement exhausted worker storage is explicit instead of hidden delivery loss" {
    var ctx = try Context.init(std.testing.allocator, 2001, 1, 1000, std.testing.io);
    defer ctx.deinit();
    const nonce: [16]u8 = @splat(3);
    _ = try beginTest(&ctx, nonce, 2001, test_owner, 1);
    const thread = try std.Thread.spawn(.{}, concurrentData, .{ &ctx, @as(u32, 0) });
    thread.join();
    const stats = try readTest(&ctx, nonce, 2000);
    try std.testing.expect(stats.tracking_failed);
    try std.testing.expectEqual(@as(u64, 0), stats.received);
}
