/// coapd — High-performance CoAP server on io_uring.
pub const Server = @import("Server.zig");
pub const Config = Server.Config;
pub const Request = @import("handler.zig").Request;
pub const Response = @import("handler.zig").Response;
pub const HandlerFn = @import("handler.zig").HandlerFn;
pub const SimpleHandlerFn = @import("handler.zig").SimpleHandlerFn;
pub const coap = @import("coapz");

const constants = @import("constants.zig");
const Io = @import("Io.zig");
const Exchange = @import("exchange.zig");

test {
    _ = constants;
    _ = Io;
    _ = Server;
    _ = Exchange;
}
