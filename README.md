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
  - `dns.allow_authoritative`
  - `doh.enabled`
- DNS resolution caching for allowed domains
- Optional DoH inspection mode (`doh.enabled: true`)
- Configuration hot-reload (automatically reloads on file change)

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
# Default behavior: load ./egress-allowlist.yaml
./target/release/egress-filter curl https://example.com

# Use a policy file
./target/release/egress-filter -c egress-allowlist.yaml curl https://api.anthropic.com

# Disable filtering (allow all)
./target/release/egress-filter --allow-all npm install
```

Without `--allow-all`, a policy file must be loadable (`-c <path>` or `./egress-allowlist.yaml`).

## Configuration

Example `egress-allowlist.yaml`:

```yaml
version: 1
default_policy: deny

dns:
  # Allow outbound DNS server connections (port 53) to any IP.
  # Useful for iterative resolvers that contact authoritative servers directly.
  allow_authoritative: false

doh:
  enabled: true

domains:
  - pattern: "github.com"
    ports: [22, 443]
  - pattern: "*.github.com"
    ports: [443]

ip_ranges:
  # Localhost
  - cidr: "127.0.0.0/8"
  - cidr: "::1/128"
  - cidr: "::ffff:127.0.0.0/104"

  # LAN
  - cidr: "10.0.0.0/8"
  - cidr: "172.16.0.0/12"
  - cidr: "192.168.0.0/16"

  # Cloudflare DNS
  - cidr: "1.1.1.1/32"
    ports: [53, 443]
  - cidr: "1.0.0.1/32"
    ports: [53, 443]
```

Field notes:

- `default_policy`: `deny` or `allow`
- `domains[].ports`: `null` (or omitted) means all ports
- `ip_ranges[].cidr`: CIDR or single IP
- `ip_ranges[].ports`: `null` (or omitted) means all ports
- `dns.allow_authoritative`: allow DNS server connects (port 53) to any IP
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

## Hot-Reload

When policy loading is enabled (default, or via `-c`), the supervisor watches the active configuration file and automatically reloads the allowlist. This allows updating rules without restarting the supervised process.

The watcher uses debouncing (500ms) to handle editors that save files in multiple steps.

If watcher startup fails, egress filtering continues with the initially loaded configuration.

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
