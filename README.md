# VESPER-OS-TCP-IP-STACK

A minimal TCP/IP stack built from scratch for **VESPER OS** — a bare-metal x86
operating system written in Assembly (bootloader) and C (kernel) with no libc
or external networking dependencies.

---

## Architecture

```
VESPER-OS-TCP-IP-STACK/
├── include/          # Public header files
│   ├── types.h       # Bare-metal type definitions (uint8_t, bool, byte-order macros)
│   ├── ethernet.h    # Ethernet II frame structures and API
│   ├── ip.h          # IPv4 header structures and API
│   ├── tcp.h         # TCP header, state machine, and API
│   ├── nic.h         # NIC driver abstraction layer
│   ├── net.h         # High-level kernel-facing network interface
│   └── klog.h        # Minimal kernel serial logging
├── ethernet/
│   └── ethernet.c    # Frame construction, parsing, MAC helpers
├── ip/
│   └── ip.c          # IPv4 packet build/parse, RFC-1071 checksum
├── tcp/
│   └── tcp.c         # TCP segment build/parse, checksum, state machine
├── drivers/
│   └── nic_stub.c    # Loopback NIC stub (ring buffer, no real hardware needed)
├── net/
│   ├── net.c         # Top-level subsystem init, TCP connect loop, send, close
│   └── klog.c        # COM1 serial output (bare-metal) / stdout (host tests)
├── tests/
│   ├── test_main.c   # Test runner
│   ├── test_ethernet.c
│   ├── test_ip.c
│   └── test_tcp.c
├── main.c            # Kernel entry point demo
└── Makefile
```

---

## Features

| Layer    | Implemented                                              |
|----------|----------------------------------------------------------|
| Ethernet | Frame construction, parsing, EtherType handling           |
| IPv4     | Header build/parse, RFC-1071 checksum, TTL, DF flag      |
| TCP      | SYN / SYN-ACK / ACK / PSH+ACK / FIN+ACK segments        |
| TCP FSM  | CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1            |
| NIC      | Stub loopback driver with TX ring buffer                 |
| Logging  | COM1 serial output for all protocol events               |

---

## Building

### Run unit tests on a Linux host

```bash
make test
```

No cross-compiler required. The Makefile uses the system `gcc` and passes
`-DTEST_HOST` so the serial-port I/O is replaced by `putchar()`.

### Build the static library only

```bash
make
```

Produces `build/libnet.a`.

### Bare-metal cross-compile (requires i686-elf-gcc)

```bash
make CROSS=1
```

---

## Protocol compliance

* **Ethernet II** — IEEE 802.3 frame layout, big-endian EtherType
* **IPv4** — RFC 791, 20-byte fixed header, DF bit, TTL=64
* **IP checksum** — RFC 1071 one's complement algorithm
* **TCP** — RFC 793, 20-byte fixed header, correct pseudo-header checksum
* **TCP sequence numbers** — RFC 6528-style ISN counter per connection

---

## TCP Handshake flow

```
VESPER OS (client)          Remote host (server)
      |                            |
      |------- SYN (seq=ISN) ----->|     state: CLOSED -> SYN_SENT
      |                            |
      |<-- SYN-ACK (ack=ISN+1) ----|     state: (server opens)
      |                            |
      |------- ACK -------------->|     state: SYN_SENT -> ESTABLISHED
      |                            |
      |--- PSH+ACK "Hello..." ---->|     data transfer
      |                            |
      |------- FIN+ACK ----------->|     state: ESTABLISHED -> FIN_WAIT_1
```

---

## Usage (from kernel code)

```c
#include "net.h"

net_config_t cfg = {
    .local_ip   = ip_make_addr(192, 168, 1, 10),
    .gateway_ip = ip_make_addr(192, 168, 1, 1),
    .netmask    = ip_make_addr(255, 255, 255, 0),
    .gateway_mac = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02},
};
net_init(&cfg);

tcp_conn_t conn;
if (net_tcp_connect(&conn, 49152,
                    ip_make_addr(192, 168, 1, 1), 8080)) {
    net_tcp_send(&conn,
                 (const uint8_t *)"Hello from VESPER", 17);
    net_tcp_close(&conn);
}
```
