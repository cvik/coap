# Server I/O optimizations

This change ports the measured five-part native io_uring prototype without
changing CoAP response-cache policy or the public server API. A follow-up commit
pins the independently released coapz v0.4.0 parser optimization.

- `COOP_TASKRUN` reduces cross-CPU task-work notifications. No `SINGLE_ISSUER`,
  `DEFER_TASKRUN`, or SQPOLL restriction is introduced; existing thread-handoff
  fixtures remain supported.
- One pending 50-ms tick timeout preserves idle shutdown/maintenance wakeups
  without queuing a fresh timeout for every busy tick. Timeout CQEs clear the
  pending state; submission errors propagate instead of being silently ignored.
- A shared provided-buffer descriptor ring returns buffers without a return SQE
  or CQE. Incremental consumption is disabled: one datagram consumes one buffer.
  Plaintext packets are decoded into the existing arena, and DTLS datagrams are
  copied, before returning their receive buffer. Close io_uring before unmapping
  the descriptor ring; never unregister through a potentially reused fd.
- The bound socket occupies registered-file slot zero for receive and send.
  The ordinary descriptor remains owned until teardown; closing the ring releases
  its registered reference. This was a marginal performance improvement, retained
  as part of the explicitly selected full chain.
- Completed exchanges have preallocated address-hash buckets and intrusive links.
  Peer eviction visits its bucket instead of scanning every slot. All removal
  paths unlink both indexes. Matching still uses the existing full `addr_key`;
  hash grouping, rejection, expiry, cached responses and retransmission behavior
  are unchanged. This is not a new RFC exchange-lifetime guarantee.

The descriptor ring adds page-rounded locked memory, accounted for in the
existing approximate memlock clamp. Payload buffers are not pinned. Peer indexing
adds two links per slot (using existing padding on the measured x86_64 target),
a slice header and `2 * table_size` bytes of bucket heads: 1,024 bytes at the
default 256 exchanges. Init allocates this storage; peer eviction does not allocate.

## Evidence and limits

Independent, alternating native loopback experiments used Zig 0.16.0, Linux
7.1.11, Ryzen AI MAX+ 395, one server thread, 100-byte payloads and W8/client.
The five parts were evaluated incrementally: COOP improved a single-client CON
case about 5.5%; one timer was about 1%; provided buffers improved four-client
CON about 7.9%; registered socket about 1%; peer indexing about 6.4%. These are
**different matched comparisons, not additive gains or a universal speedup**.
Four clients are not server-worker scaling. No libcoap performance ranking is
claimed here. Raw exploratory archives remain separate from this focused PR.

Coverage includes repeated idle timer wakeups, held/exhausted/resumed receive
buffers, no SQE publication on buffer return, registered-socket operation after
closing the original descriptor, allocation-failure cleanup, index collision/
unlink/expiry/reuse and 5,000 operations against a scan model. Existing benchmark
integration covers IPv4/IPv6, native UDP/DTLS, two server workers and client windows.

Linux 6.0+ is required by the existing multishot recvmsg path. Shared descriptor
rings and COOP are supported within that floor. Older kernels, overload/lifecycle
patterns and different CPUs still warrant workload-specific validation. No empty
submission skipping or CQE-clearing removal is included. The I/O measurements
above used the original coapz v0.3.0 dependency. The subsequent v0.4.0 pin also
includes its independently released inline-helper fix; parser/end-to-end gains
are not attributed to the five I/O changes.
