# allnodes-xdp

AF_XDP for Linux services. Several programs can share one interface through it, and
each gets the fast path it needs:

- **A shared XDP hook.** A libxdp-compatible dispatcher holds every program on the
  interface. Each member of ours keeps a marker while its owner runs, steering rules are
  recorded per owner, and whatever a killed process leaves behind is removed by the next
  one. Programs that follow this protocol, including earlier builds that called their
  member `agave_xdp_rx`, coexist on one NIC.
- **Send engines.** Transmit loops on dedicated cores, an 802.3ad bond sender, VLAN and
  GRE encapsulation (`transmitter`, `tx_loop`).
- **Receive engines.** UDP receive by port with a queue plan and RSS contexts (`runtime`,
  `rx`, `plan`), and an `XdpQuicSocket` for quinn endpoints (`XdpContext`).

The modules at the crate root keep the layout of Agave's `xdp` crate, from which many of
them derive, so its changes merge file by file. The Agave validator forks keep a thin
`agave_xdp` facade over this crate.

## Endpoint front end (QUIC)

```rust
use allnodes_xdp::{EndpointSpec, XdpContext, XdpSettings};

// Reads MYAPP_NET_XDP, MYAPP_NET_XDP_MODE, ... `None` when the switch is off.
let Some(settings) = XdpSettings::from_env("MYAPP_")? else { return Ok(()) };

// Blocking; call it at startup from a thread that is not pinned to a latency core.
let ctx = XdpContext::new(&settings, &[EndpointSpec { name: "quic", listen: "0.0.0.0:7000".parse()? }])?;

let socket = ctx.socket("quic")?; // Arc<XdpQuicSocket>
let endpoint = quinn::Endpoint::new_with_abstract_socket(
    quinn::EndpointConfig::default(),
    Some(server_config),
    socket,
    std::sync::Arc::new(quinn::TokioRuntime),
)?;

// Before dialing a peer: resolve its route and neighbor.
ctx.prepare(peer_addr).await?;

// At exit: close the endpoints first, then:
ctx.shutdown(); // blocking
```

Dropping the last handle runs the same `shutdown()`. Calling it explicitly picks the moment
and the thread: it blocks for seconds, so async code runs it in `spawn_blocking`.

`ctx.failed()` and `ctx.wait_failed()` report a context that can no longer work
(program detached, device lost, ...). A failed context does not recover; build a new one.

### Settings

`XdpSettings::from_env(prefix)` reads these variables; the library reads nothing by itself.

| Variable | Default | Meaning |
|---|---|---|
| `<prefix>NET_XDP` | `false` | Switch. The other variables are errors while it is off. |
| `<prefix>NET_XDP_INTERFACE` | auto | Interface or LACP bond. Auto = the interface of the default route. |
| `<prefix>NET_XDP_MODE` | `drv` | `drv` (native) or `skb` (generic, works with every driver). |
| `<prefix>NET_XDP_ZERO_COPY` | `false` | Zero-copy sockets. Needs `drv` and driver support. |
| `<prefix>NET_XDP_NATIVE_BOND` | `false` | Attach to the ports of a bond in native mode. |

## Requirements and limits

- Linux, IPv4 only. Destinations on the host itself go through the kernel.
- Root, or `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF`, `CAP_PERFMON` and `CAP_SYS_ADMIN`.
- A bpf filesystem at `/sys/fs/bpf` and `RLIMIT_MEMLOCK` of at least 16 MiB per socket.
- XDP traffic is not filtered by iptables or nftables.
- Some drivers restart the port when a native program is attached or detached. On a bond
  the ports are handled one at a time, so the bond stays up.

## After a crash

A killed process leaves its program, steering rules and ownership record behind. The
next context started on the host removes them. `reap_dead_leftovers()` does the same
without starting anything and returns a `CleanupReport`.

## eBPF objects

Both programs are prebuilt in `objects/` from `ebpf/` and rebuilt reproducibly with
`scripts/build-ebpf.sh` (nightly-2025-12-05, bpf-linker 0.9.15):

| File | Program | sha256 |
|---|---|---|
| `allnodes-xdp-classifier` | `allnodes_xdp_rx` | `8199dd7f3a041ff5e34d08a1f8eb79750ba18679e2b24ae609f06140f4d9eb23` |
| `allnodes-xdp-dispatcher` | `xdp_dispatcher` (GPL-2.0) | `91bec198c959f52e65999cb400c29ec35d38962c71e5677b795395fda4ba0d35` |

## MSRV

Rust 1.93.

## License

Apache-2.0, except the dispatcher program (`ebpf/src/bin/allnodes-xdp-dispatcher.rs`
and `objects/allnodes-xdp-dispatcher`), which is GPL-2.0. Parts derive from Agave and
libxdp; see `NOTICE`.
