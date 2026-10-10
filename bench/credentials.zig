const std = @import("std");
const coap = @import("coap");
pub const Credentials = struct {
    identity: [128]u8 = @splat(0),
    identity_len: usize = 0,
    key: [64]u8 = @splat(0),
    key_len: usize = 0,
    pub fn psk(self: *const Credentials) coap.Psk {
        return .{ .identity = self.identity[0..self.identity_len], .key = self.key[0..self.key_len] };
    }
    pub fn clear(self: *Credentials) void {
        std.crypto.secureZero(u8, &self.key);
    }
    pub fn parse(bytes: []const u8) !Credentials {
        if (bytes.len > 2048) return error.CredentialFileTooLarge;
        var scratch: [8192]u8 = undefined;
        defer std.crypto.secureZero(u8, &scratch);
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        const parsed = try std.json.parseFromSlice(struct { identity: []const u8, key_hex: []const u8 }, fba.allocator(), bytes, .{});
        defer parsed.deinit();
        const value = parsed.value;
        if (value.identity.len == 0 or value.identity.len > 128 or value.key_hex.len < 32 or value.key_hex.len > 128 or value.key_hex.len % 2 != 0) return error.InvalidCredentials;
        var result: Credentials = .{};
        errdefer result.clear();
        @memcpy(result.identity[0..value.identity.len], value.identity);
        result.identity_len = value.identity.len;
        const key = try std.fmt.hexToBytes(&result.key, value.key_hex);
        result.key_len = key.len;
        return result;
    }
    pub fn load(path: []const u8) !Credentials {
        var path_buffer: [std.fs.max_path_bytes + 1]u8 = undefined;
        const zpath = try std.fmt.bufPrintSentinel(&path_buffer, "{s}", .{path}, 0);
        const fd = try coap.platform.open(zpath, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        defer coap.platform.close(fd);
        var buffer: [2049]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        var length: usize = 0;
        while (length < buffer.len) {
            const rc = std.os.linux.read(fd, buffer[length..].ptr, buffer.len - length);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.CredentialReadFailed,
            }
            if (rc == 0) break;
            length += rc;
        }
        if (length == buffer.len) return error.CredentialFileTooLarge;
        return parse(buffer[0..length]);
    }
};
test "PSK rejects duplicate fields, invalid hex and oversized input; clears owned key" {
    const oversized: [2049]u8 = @splat(' ');
    try std.testing.expectError(error.CredentialFileTooLarge, Credentials.parse(&oversized));
    try std.testing.expectError(error.DuplicateField, Credentials.parse("{\"identity\":\"a\",\"identity\":\"b\",\"key_hex\":\"30313233343536373839616263646566\"}"));
    try std.testing.expectError(error.InvalidCharacter, Credentials.parse("{\"identity\":\"a\",\"key_hex\":\"zz313233343536373839616263646566\"}"));
    var c = try Credentials.parse("{\"identity\":\"a\",\"key_hex\":\"30313233343536373839616263646566\"}");
    c.clear();
    try std.testing.expect(std.mem.allEqual(u8, &c.key, 0));
}

test "PSK file parsing is bounded and strict" {
    var c = try Credentials.parse("{\"identity\":\"bench\",\"key_hex\":\"30313233343536373839616263646566\"}");
    defer c.clear();
    try std.testing.expectEqualStrings("0123456789abcdef", c.psk().key);
    try std.testing.expectError(error.InvalidCredentials, Credentials.parse("{\"identity\":\"\",\"key_hex\":\"00\"}"));
    try std.testing.expectError(error.UnknownField, Credentials.parse("{\"identity\":\"a\",\"key_hex\":\"00\",\"extra\":1}"));
}
