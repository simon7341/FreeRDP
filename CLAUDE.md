# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache 2.0 license. It provides both client and server implementations across multiple platforms (Linux, Windows, macOS, iOS, Android).

## Build Commands

### Basic Build
```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Build with All Features (Linux)
```bash
mkdir build && cd build
cmake -C ../ci/cmake-preloads/config-linux-all.txt ..
cmake --build .
```

### Common CMake Options
- `-DBUILD_TESTING=ON` - Build unit tests (for packaging)
- `-DBUILD_TESTING_INTERNAL=ON` - Build internal unit tests (CI only)
- `-DWITH_SERVER=ON` - Build server components
- `-DWITH_CLIENT=ON` - Build client binaries
- `-DWITH_CHANNELS=ON` - Build virtual channel plugins
- `-DWITH_FFMPEG=ON` - Enable FFmpeg for audio/video

### Running Tests
```bash
cd build
ctest --output-on-failure
```

### Running a Single Test
```bash
cd build
ctest -R TestName --output-on-failure
```

### Code Formatting
```bash
# Format with clang-format (if WITH_CLANG_FORMAT=ON)
cmake --build build --target clangformat
```

## Architecture

### Core Libraries

- **winpr/** - Windows Portable Runtime: Cross-platform abstraction layer providing Windows API equivalents (threads, synchronization, crypto, file I/O, registry, SSPI, etc.). Must be built first as all other components depend on it.

- **libfreerdp/** - Core RDP protocol implementation:
  - `core/` - RDP protocol state machine, connection handling, capabilities negotiation
  - `codec/` - Image codecs (RFX, NSC, H.264, etc.)
  - `crypto/` - Cryptographic operations, certificate handling
  - `gdi/` - Graphics Device Interface implementation
  - `cache/` - Bitmap, glyph, and other caches
  - `primitives/` - SIMD-optimized graphics primitives

- **channels/** - Virtual channel plugins (clipboard, audio, drive redirection, smartcard, etc.). Each channel has `client/` and optionally `server/` subdirectories.

### Client Implementations

- `client/X11/` - X11 client (xfreerdp)
- `client/SDL/` - SDL2/SDL3 clients
- `client/Mac/` - macOS client
- `client/Windows/` - Windows client (wfreerdp)
- `client/iOS/` - iOS client
- `client/Android/` - Android client
- `client/common/` - Shared client code

### Server Implementations

- `server/shadow/` - Shadow server (screen sharing)
- `server/proxy/` - RDP proxy server with plugin API
- `server/Sample/` - Sample server implementation

### Supporting Libraries

- **rdtk/** - RDP Toolkit for server-side rendering
- **uwac/** - Using Wayland As Client library

## Code Style

- Uses Allman brace style (braces on their own lines)
- 4-space indentation with tabs
- 100 character line limit
- Pointer alignment: left (`char* ptr`)
- Configured via `.clang-format` and `.clang-tidy`

## Logging (WLog)

Configure logging via environment variables:
- `WLOG_LEVEL` - Log level: TRACE, DEBUG, INFO, WARN, ERROR, FATAL, OFF
- `WLOG_FILTER` - Filter specific loggers
- `WLOG_APPENDER` - Output target: CONSOLE, FILE, SYSLOG, JOURNALD, UDP

Example:
```bash
WLOG_LEVEL=DEBUG WLOG_PREFIX="pid=%pid:tid=%tid:fn=%fn -" xfreerdp /v:host
```

## Print Format Specifiers

Use portable format specifiers for Windows types:
- `UINT32` → `%"PRIu32"`, `UINT64` → `%"PRIu64"`
- `size_t` → `%"PRIuz"`
- Pointers → cast to `(void*)` with `%p`

## Proxy Module Development

Proxy plugins go in `server/proxy/modules/`. Modules must:
1. Include `freerdp/server/proxy/proxy_modules_api.h`
2. Implement `proxy_module_entry_point` function
3. Be installed as `proxy-<name>-plugin.so` in `lib/freerdp3/proxy/`

## Key Header Locations

- `include/freerdp/` - Public FreeRDP API
- `winpr/include/winpr/` - Public WinPR API
- `include/freerdp/channels/` - Channel-specific headers

## Architecture Documentation

Detailed architecture documentation is available in `docs/`:

- [docs/architecture-overview.md](docs/architecture-overview.md) - High-level system architecture
- [docs/libfreerdp-architecture.md](docs/libfreerdp-architecture.md) - Core RDP library internals
- [docs/winpr-architecture.md](docs/winpr-architecture.md) - Windows Portable Runtime details
- [docs/channels-architecture.md](docs/channels-architecture.md) - Virtual channel plugins
