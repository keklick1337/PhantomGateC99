# PhantomGate (C99)

( **_C99 VERSION [current]_** | **[PYTHON VERSION](https://github.com/keklick1337/PhantomGate)** )

**PhantomGate (C99)** is a minimalistic port spoofer, fully rewritten from the original Python version by the same author. It responds with fake or randomized signatures to confuse port scanners.

> Created by **Vladislav Tislenko (aka keklick1337)**

## Features
- Minimal dependencies (plain C99 and pthreads).
- Simple configuration via command-line flags (`--debug`, `--quiet`, etc.).
- Signature file supports both raw and regex-like lines.
- Basic randomization of responses.

## Download
Precompiled binaries (for multiple architectures) are available on the [Release Page](https://github.com/keklick1337/PhantomGateC99/releases).

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
   - `-s signatures.txt` – specify the signature file.  
   - `-l 0.0.0.0:8888` – listen on all interfaces, port **8888**.  
   - `-v` – enable verbose output.

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