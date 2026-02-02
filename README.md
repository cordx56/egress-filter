# egress-filter

`egress-filter` is a Linux egress filter for running commands under outbound network policy control.
It uses seccomp user notification to intercept network syscalls and enforce an allow list defined in YAML.

## Features

- Intercepts `connect`, `sendto`, `send`, and `sendmmsg`
- Supports IPv4/IPv6 destination filtering
- Domain-based filtering via DNS query parsing (UDP/53)
- YAML policy with:
  - `default_policy`
  - `domains` (exact and wildcard patterns like `*.example.com`)
  - `ip_ranges` (CIDR or single IP)
  - `doh.enabled`
- DNS resolution caching for allowed domains
- Optional DoH inspection mode (`doh.enabled: true`)

## Requirements

- Linux kernel 5.0+ (`SECCOMP_RET_USER_NOTIF`)
- `libseccomp` development package
  - Debian/Ubuntu: `apt install libseccomp-dev`

## Build

```bash
cargo build --release
```

## CLI Usage

```bash
# Default behavior: deny all outbound traffic
./target/release/egress-filter curl https://example.com

# Use a policy file
./target/release/egress-filter -c egress-allowlist.yaml curl https://api.anthropic.com

# Disable filtering (allow all)
./target/release/egress-filter --allow-all npm install
```

## Configuration

Example `egress-allowlist.yaml`:

```yaml
version: 1
default_policy: deny

doh:
  enabled: true

domains:
  - pattern: "api.anthropic.com"
    ports: [443]
    reason: Claude API
  - pattern: "*.github.com"
    ports: [443]

ip_ranges:
  - cidr: "127.0.0.53/32"
    ports: [53]
  - cidr: "10.0.0.0/8"
```

Field notes:

- `default_policy`: `deny` or `allow`
- `domains[].ports`: `null` (or omitted) means all ports
- `ip_ranges[].cidr`: CIDR or single IP
- `ip_ranges[].ports`: `null` (or omitted) means all ports
- `doh.enabled`: enables HTTPS proxy + DoH request inspection

## DoH Mode

When `doh.enabled: true`, the supervisor:

- starts a local TLS-terminating proxy
- generates an ephemeral CA certificate
- injects CA-related environment variables into the child process:
  - `EGRESS_FILTER_CA_CERT`
  - `SSL_CERT_FILE`
  - `CURL_CA_BUNDLE`
  - `NODE_EXTRA_CA_CERTS`
  - `REQUESTS_CA_BUNDLE`
- inspects DoH queries against the allow list

When `doh.enabled: false`, DoH MITM/inspection and CA injection are disabled.
Normal syscall-level destination filtering is still active.

## Library Usage

```rust
use egress_filter::{Supervisor, AllowListConfig};

let config = AllowListConfig::load("egress-allowlist.yaml")?;
let supervisor = Supervisor::new(config);
let exit_code = supervisor.run(&["curl", "https://example.com"])?;
```

## Logging

Use `RUST_LOG` to control log level:

```bash
RUST_LOG=debug ./target/release/egress-filter -c egress-allowlist.yaml curl https://example.com
```

## License

MIT
