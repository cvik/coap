//! Bounded, allocation-free CoAP decoding. All returned bytes borrow the wire
//! buffer; option descriptors borrow caller-provided storage. Never deinit the
//! returned coapz.Packet with an allocator.
const std = @import("std");
const coapz = @import("coapz");

pub const Error = coapz.Error || error{ ResponseOptionsTooSmall, InvalidOption };

fn extended(data: []const u8, pos: *usize, nibble: u4) Error!u16 {
    switch (nibble) {
        0...12 => return nibble,
        13 => {
            if (pos.* >= data.len) return error.TruncatedOption;
            const value: u16 = @as(u16, data[pos.*]) + 13;
            pos.* += 1;
            return value;
        },
        14 => {
            if (data.len - pos.* < 2) return error.TruncatedOption;
            const raw = std.mem.readInt(u16, data[pos.*..][0..2], .big);
            pos.* += 2;
            return std.math.add(u16, raw, 269) catch error.InvalidOption;
        },
        15 => return error.InvalidOption,
    }
}

pub fn read(data: []const u8, options: []coapz.Option) Error!coapz.Packet {
    if (data.len < 4) return error.MessageTooShort;
    if (data[0] >> 6 != 1) return error.InvalidVersion;
    const tkl: usize = data[0] & 15;
    if (tkl > 8) return error.InvalidTokenLength;
    if (data.len < 4 + tkl) return error.MessageTooShort;
    var pos: usize = 4 + tkl;
    var count: usize = 0;
    var kind: u16 = 0;
    var payload: []const u8 = &.{};
    while (pos < data.len) {
        const header = data[pos];
        pos += 1;
        if (header == 255) {
            if (pos == data.len) return error.EmptyPayload;
            payload = data[pos..];
            break;
        }
        const delta = try extended(data, &pos, @truncate(header >> 4));
        const len = try extended(data, &pos, @truncate(header));
        kind = std.math.add(u16, kind, delta) catch return error.InvalidOption;
        if (len > data.len - pos) return error.TruncatedOption;
        if (count >= options.len) return error.ResponseOptionsTooSmall;
        options[count] = .{ .kind = @enumFromInt(kind), .value = data[pos..][0..len] };
        count += 1;
        pos += len;
    }
    return .{ .kind = @enumFromInt((data[0] >> 4) & 3), .code = @enumFromInt(data[1]), .msg_id = std.mem.readInt(u16, data[2..4], .big), .token = data[4..][0..tkl], .options = options[0..count], .payload = payload, .data_buf = &.{} };
}

test "packet view decodes extended lengths, deltas, and repeated options" {
    const a = [_]u8{7} ** 13;
    const b = [_]u8{9} ** 269;
    const packet: coapz.Packet = .{ .kind = .confirmable, .code = .content, .msg_id = 500, .token = "12345678", .payload = "end", .data_buf = &.{}, .options = &.{ .{ .kind = .uri_path, .value = &a }, .{ .kind = .uri_path, .value = &.{} }, .{ .kind = .size1, .value = &b }, .{ .kind = @enumFromInt(64000), .value = "x" } } };
    var wire: [1024]u8 = undefined;
    const data = try packet.writeBuf(&wire);
    var options: [4]coapz.Option = undefined;
    const view = try read(data, &options);
    try std.testing.expectEqualSlices(u8, packet.token, view.token);
    try std.testing.expectEqualSlices(u8, packet.payload, view.payload);
    for (packet.options, view.options) |expected, actual| {
        try std.testing.expectEqual(expected.kind, actual.kind);
        try std.testing.expectEqualSlices(u8, expected.value, actual.value);
    }
}

test "packet view rejects malformed headers, options, and truncated extensions" {
    var options: [4]coapz.Option = undefined;
    try std.testing.expectError(error.MessageTooShort, read(&.{ 0x40, 0x45, 0 }, &options));
    try std.testing.expectError(error.InvalidVersion, read(&.{ 0x80, 0x45, 0, 0 }, &options));
    try std.testing.expectError(error.InvalidTokenLength, read(&.{ 0x49, 0x45, 0, 0 }, &options));
    try std.testing.expectError(error.MessageTooShort, read(&.{ 0x48, 0x45, 0, 0 }, &options));
    try std.testing.expectError(error.TruncatedOption, read(&.{ 0x40, 0x45, 0, 0, 0xd0 }, &options));
    try std.testing.expectError(error.TruncatedOption, read(&.{ 0x40, 0x45, 0, 0, 0x0e, 0 }, &options));
    try std.testing.expectError(error.TruncatedOption, read(&.{ 0x40, 0x45, 0, 0, 0x03, 1 }, &options));
    try std.testing.expectError(error.InvalidOption, read(&.{ 0x40, 0x45, 0, 0, 0xf0 }, &options));
    try std.testing.expectError(error.InvalidOption, read(&.{ 0x40, 0x45, 0, 0, 0x0f }, &options));
    try std.testing.expectError(error.InvalidOption, read(&.{ 0x40, 0x45, 0, 0, 0xe0, 255, 255 }, &options));
}

test "bounded packet view matches allocating decoder and rejects insufficient options" {
    const wire = [_]u8{ 0x42, 0x45, 0x12, 0x34, 'a', 'b', 0xb1, 'x', 0xff, 'o', 'k' };
    var options: [1]coapz.Option = undefined;
    const view = try read(&wire, &options);
    const owned = try coapz.Packet.read(std.testing.allocator, &wire);
    defer owned.deinit(std.testing.allocator);
    try std.testing.expectEqual(owned.kind, view.kind);
    try std.testing.expectEqual(owned.code, view.code);
    try std.testing.expectEqual(owned.msg_id, view.msg_id);
    try std.testing.expectEqualSlices(u8, owned.token, view.token);
    try std.testing.expectEqualSlices(u8, owned.payload, view.payload);
    try std.testing.expectEqual(owned.options[0].kind, view.options[0].kind);
    try std.testing.expectEqualSlices(u8, owned.options[0].value, view.options[0].value);
    try std.testing.expectError(error.ResponseOptionsTooSmall, read(&wire, &.{}));
    try std.testing.expectError(error.EmptyPayload, read(wire[0..9], &options));
}
