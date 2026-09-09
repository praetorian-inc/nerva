<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->

# nerva CLI reference

Every command, alias and flag below is derived from the cobra command tree, not from prose.
Schema version 1, surface hash `sha256:fb62443a537e4b658be930ce6a9944a72a27b80a6661977e5062b440b3bfeb86`.

Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.

## Command index

| Command | Aliases | Description |
| --- | --- | --- |
| [`nerva`](#nerva) | *(none)* |  |

## `nerva`

- Usage: `nerva [flags]
TARGET SPECIFICATION:
	Requires a host and port number or ip and port number. The port is assumed to be open.
	HOST:PORT or IP:PORT
EXAMPLES:
	nerva -t praetorian.com:80
	nerva -l input-file.txt
	nerva --json -t praetorian.com:80,127.0.0.1:8000`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--auto-save` |  | int | `0` | auto-save interval (number of targets) |
| `--capabilities` | `-c` | bool | `false` | list available capabilities and exit |
| `--csv` |  | bool | `false` | output format in csv |
| `--deep` |  | bool | `false` | enable deep probing (admin paths, login detection) |
| `--dns-order` |  | string | `lp` | DNS resolution order: p, l, lp, pl |
| `--fast` | `-f` | bool | `false` | fast mode |
| `--json` |  | bool | `false` | output format in json |
| `--list` | `-l` | string |  | input file containing targets |
| `--max-host-conn` | `-H` | int | `0` | max concurrent connections per host IP (0=unlimited) |
| `--misconfigs` |  | bool | `false` | enable security misconfiguration detection |
| `--output` | `-o` | string |  | output file |
| `--proxy` |  | string |  | proxy URL (e.g. socks5://127.0.0.1:1080) |
| `--proxy-auth` |  | string |  | socks5 proxy authentication (username:password) |
| `--rate-limit` | `-R` | float64 | `0` | max scans per second (0=unlimited) |
| `--scan-depth` |  | string |  | scan depth mode: "fast" or "thorough" (default: legacy behavior governed by --fast). fast: only tries plugins whose port priority matches the target port, skipping the full plugin iteration for non-standard ports; equivalent to --fast. thorough: tries all plugins regardless of port (current default behavior); slowest but most complete. Banner-based pre-filtering is planned for a future release and is not yet implemented. Takes precedence over --fast if both are set (--fast is deprecated in that case). |
| `--sctp` | `-S` | bool | `false` | run SCTP plugins (Linux only) |
| `--targets` | `-t` | stringSlice | `[]` | target or comma separated target list |
| `--timeout` | `-w` | int | `2000` | timeout (milliseconds) |
| `--udp` | `-U` | bool | `false` | run UDP plugins |
| `--verbose` | `-v` | bool | `false` | verbose mode |
| `--workers` | `-W` | int | `50` | number of concurrent scan workers |
