# PhantomGate (C99)
![c99 version](https://img.shields.io/badge/Pure-C99-green?logo=c)
( **_C99 VERSION [current]_** | **[PYTHON VERSION](https://github.com/keklick1337/PhantomGate)** )

**PhantomGate (C99)** is a minimalistic port spoofer, fully rewritten from the original Python version by the same author. It responds with fake or randomized signatures to confuse port scanners.

> Created by **Vladislav Tislenko (aka keklick1337)**

## Features
- Minimal dependencies (plain C99 and pthreads).
- Simple configuration via command-line flags (`--debug`, `--quiet`, etc.).
- Signature file supports both raw and regex-like lines.
- Basic randomization of responses.
- **Optional logging to file** (`--logfile` or `-f`) with timestamps.
- **Client reporting** (`--report-clients` or `-r`) to show which signature was sent to each client.

## Download
Precompiled binaries (for multiple architectures) are available on the [Release Page](https://github.com/keklick1337/PhantomGateC99/releases).  

| Platform   | Download                                                                                                                        |
|------------|---------------------------------------------------------------------------------------------------------------------------------|
| Linux **x86_64**  | [![Download x86_64](https://img.shields.io/badge/x86__64-Latest-blueviolet?logo=github)](https://github.com/keklick1337/PhantomGateC99/releases/latest/download/phantomgate_x86_64.tar.gz)     |
| Linux **aarch64** | [![Download aarch64](https://img.shields.io/badge/aarch64-Latest-brightgreen?logo=github)](https://github.com/keklick1337/PhantomGateC99/releases/latest/download/phantomgate_aarch64.tar.gz) |
| Linux **armv7**   | [![Download armv7](https://img.shields.io/badge/armv7-Latest-blue?logo=github)](https://github.com/keklick1337/PhantomGateC99/releases/latest/download/phantomgate_armv7.tar.gz)               |
| Linux **mips**    | [![Download mips](https://img.shields.io/badge/mips-Latest-red?logo=github)](https://github.com/keklick1337/PhantomGateC99/releases/latest/download/phantomgate_mips.tar.gz)                   |
| Linux **riscv64** | [![Download riscv64](https://img.shields.io/badge/riscv64-Latest-yellow?logo=github)](https://github.com/keklick1337/PhantomGateC99/releases/latest/download/phantomgate_riscv64.tar.gz)       |
| Linux **i386**    | [![Download i386](https://img.shields.io/badge/i386-Latest-orange?logo=github)](https://github.com/keklick1337/PhantomGateC99/releases/latest/download/phantomgate_i386.tar.gz)               |

## Quick Start

1. **Clone or Download** this repository (make sure `signatures.txt` is in the same directory as `phantomgate`).
2. **Build**:
   ```bash
   ./configure
   make
   ```
   Or compile manually:
   ```bash
   gcc -std=c99 src/phantomgate.c -o phantomgate -pthread
   ```
3. **Run**:
   ```bash
   ./phantomgate -s signatures.txt -l 0.0.0.0:8888 -v
   ```
   - `-s, --signatures` – specify the signature file (default: `signatures.txt`).  
   - `-l, --listen` – listen on a given host:port (default: `127.0.0.1:8888`).  
   - `-d, --debug` – enable debug output (shows debug logs).  
   - `-v, --verbose` – enable verbose output (info-level logs).  
   - `-q, --quiet` – only show error messages.  
   - `-r, --report-clients` – show which signature was sent to each client (includes debug info).  
   - `-f, --logfile` – path to a logfile for saving all logs with timestamps.  
   - `-V, --version` – show version and exit.

Example usage with new arguments:
```bash
./phantomgate -s signatures.txt \
              -l 0.0.0.0:8888 \
              -r \
              -f myphantom.log
```
Here, PhantomGate listens on **all interfaces**, **port 8888**, logs to the file **myphantom.log**, and prints which signature was sent to each client.

## Redirecting All Traffic

To direct all incoming traffic for ports 1–65535 to PhantomGate’s port on **Linux**, you can use `iptables`:
```bash
INTERFACE="eth0"  # Replace with your network interface
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp -m tcp \
  -m multiport --dports 1:65535 -j REDIRECT --to-ports 8888
```
Then **PhantomGate** will effectively spoof any connection attempt on your machine.
For more examples you can check [Iptables Examples](examples)

## Signature File
- **Raw** lines: no parentheses or square brackets; can include `\n`, `\r`, `\xNN`.
- **Regex-like** lines: contain `(` or `[`; random expansions occur at runtime.

## Other Info
- For the Python version, see [this link](https://github.com/keklick1337/PhantomGate).  
- Author of both the original and this C99 rewrite: **keklick1337**.
- Licensed under MIT.