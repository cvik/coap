/// Default configuration values and CoAP transmission parameters.
/// RFC 7252 section 4.8.

/// Default number of provided buffers for io_uring.
/// Must exceed the max burst between tick() calls (client window size)
/// plus headroom for packets arriving during CQE processing.
/// 2x completion_batch_max handles a full burst with room to spare.
pub const buffer_count_default: u16 = 512;

/// Default buffer size in bytes (must hold a full CoAP UDP datagram).
pub const buffer_size_default: u32 = 1280;

/// Kernel buffer group identifier for provided buffers.
pub const buffer_group_id: u16 = 0;

/// Maximum completion queue entries to drain per iteration.
pub const completion_batch_max: u16 = 256;

/// Default CoAP port per RFC 7252 section 6.1.
pub const port_default: u16 = 5683;

// CoAP transmission parameters (RFC 7252 section 4.8).
pub const ack_timeout_ms: u32 = 2_000;
pub const ack_random_factor_num: u32 = 3;
pub const ack_random_factor_den: u32 = 2;
pub const max_retransmit: u4 = 4;
pub const nstart: u32 = 1;
pub const default_leisure_ms: u32 = 5_000;
pub const probing_rate_bytes_per_sec: u32 = 1;

// Derived (RFC 7252 section 4.8.2).
pub const max_transmit_span_ms: u32 = ack_timeout_ms *
    ((@as(u32, 1) << max_retransmit) - 1) *
    ack_random_factor_num / ack_random_factor_den;
pub const max_transmit_wait_ms: u32 = ack_timeout_ms *
    ((@as(u32, 1) << (max_retransmit + 1)) - 1) *
    ack_random_factor_num / ack_random_factor_den;
pub const max_latency_ms: u32 = 100_000;
pub const processing_delay_ms: u32 = ack_timeout_ms;
pub const max_rtt_ms: u32 = 2 * max_latency_ms + processing_delay_ms;
pub const exchange_lifetime_ms: u32 = max_transmit_span_ms +
    2 * max_latency_ms + processing_delay_ms;
pub const non_lifetime_ms: u32 = max_transmit_span_ms + max_latency_ms;
