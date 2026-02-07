# FreeRDP Architecture Overview

This document provides a high-level architectural overview of the FreeRDP project, explaining how the major components interact.

## Component Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Applications                       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐  │
│  │   X11   │ │   SDL   │ │  macOS  │ │ Windows │ │  Android  │  │
│  │xfreerdp │ │sdl-freer│ │  Mac    │ │wfreerdp │ │   aFree   │  │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └─────┬─────┘  │
│       └───────────┴───────────┴───────────┴─────────────┘        │
│                              │                                   │
│                    ┌─────────▼─────────┐                        │
│                    │  client/common    │                        │
│                    │ (shared client)   │                        │
│                    └─────────┬─────────┘                        │
└──────────────────────────────┼──────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────┐
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │                      libfreerdp                            │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │  │
│  │  │  core   │ │  codec  │ │   gdi   │ │   primitives    │  │  │
│  │  │ (RDP)   │ │ (media) │ │(graphics│ │ (SIMD optimize) │  │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────────────┘  │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │  │
│  │  │ crypto  │ │  cache  │ │  locale │ │     utils       │  │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │                       channels                             │  │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │  │
│  │  │cliprdr │ │rdpsnd  │ │rdpgfx  │ │ rdpdr  │ │  rail  │   │  │
│  │  │(clip)  │ │(audio) │ │(gfx)   │ │(device)│ │(remote)│   │  │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
└──────────────────────────────┼──────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────┐
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │                        winpr                               │  │
│  │              (Windows Portable Runtime)                    │  │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │  │
│  │  │ thread │ │ synch  │ │ sspi   │ │ crypto │ │  file  │   │  │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │  │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │  │
│  │  │ wlog   │ │ stream │ │smartcrd│ │ winsock│ │registry│   │  │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                        Server Applications                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │
│  │   shadow    │  │    proxy    │  │        Sample           │   │
│  │  (screen    │  │ (RDP proxy  │  │   (reference impl)      │   │
│  │   sharing)  │  │  + plugins) │  │                         │   │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘   │
│                                                                   │
│  Uses: libfreerdp (server mode) + channels (server/) + winpr     │
└──────────────────────────────────────────────────────────────────┘
```

## Layer Descriptions

### WinPR (Windows Portable Runtime)

The foundation layer providing cross-platform abstractions for Windows APIs:

- **Threading**: CreateThread, mutexes, semaphores, events, critical sections
- **I/O**: File operations, named pipes, sockets
- **Security**: SSPI (NTLM, Kerberos), cryptography, certificates
- **Utilities**: Logging (WLog), streams, command-line parsing, registry

All other components depend on WinPR. See [winpr-architecture.md](winpr-architecture.md) for details.

### libfreerdp (Core Library)

The RDP protocol implementation:

- **core/**: Protocol state machine, connection lifecycle, authentication
- **codec/**: Image/audio encoding and decoding (RFX, H.264, etc.)
- **gdi/**: 2D graphics rendering abstraction
- **crypto/**: TLS, certificates, protocol-level encryption
- **primitives/**: SIMD-optimized graphics operations
- **cache/**: Client-side caching for performance

See [libfreerdp-architecture.md](libfreerdp-architecture.md) for details.

### Channels (Virtual Channel Plugins)

Extend RDP with additional functionality:

- **Clipboard** (cliprdr): Copy/paste between local and remote
- **Audio** (rdpsnd, audin): Sound output and microphone input
- **Graphics** (rdpgfx): Modern graphics pipeline with H.264
- **Devices** (rdpdr, drive, printer, smartcard): Device redirection
- **RemoteApp** (rail): Seamless remote applications

See [channels-architecture.md](channels-architecture.md) for details.

### Client Applications

Platform-specific RDP clients built on libfreerdp:

| Client | Platform | Directory |
|--------|----------|-----------|
| xfreerdp | X11/Linux | `client/X11/` |
| sdl-freerdp | SDL2/SDL3 (cross-platform) | `client/SDL/` |
| Mac client | macOS | `client/Mac/` |
| wfreerdp | Windows | `client/Windows/` |
| iOS client | iOS | `client/iOS/` |
| aFreeRDP | Android | `client/Android/` |

Clients use `client/common/` for shared functionality like:
- Command-line parsing
- Settings management
- Channel loading

### Server Applications

RDP servers built on libfreerdp:

| Server | Purpose | Directory |
|--------|---------|-----------|
| freerdp-shadow | Screen sharing server | `server/shadow/` |
| freerdp-proxy | RDP proxy with plugin API | `server/proxy/` |
| Sample server | Reference implementation | `server/Sample/` |

### Supporting Libraries

- **rdtk/**: RDP Toolkit - server-side UI rendering
- **uwac/**: Using Wayland As Client - Wayland integration

## Data Flow

### Client Connection Flow

```
1. Client Application
   └─> freerdp_connect()
       └─> libfreerdp/core/connection.c
           ├─> nego.c (protocol negotiation)
           ├─> mcs.c, gcc.c (session setup)
           ├─> nla.c (NLA authentication via SSPI)
           ├─> license.c (licensing)
           └─> activation.c (capability exchange)

2. Graphics Updates
   Server ─> rdp.c ─> orders.c/fastpath.c
         ─> codec/ (decode)
         ─> gdi/ (render)
         ─> Client display

3. Virtual Channels
   cliprdr, rdpsnd, etc.
   └─> channels.c (dispatch)
       └─> channel plugin
           └─> Client application
```

### Server Connection Flow

```
1. Listener
   └─> listener.c (accept connection)
       └─> peer.c (create peer context)

2. Peer Handling
   └─> nego.c (negotiation)
   └─> mcs.c, gcc.c (session)
   └─> activation.c (capabilities)

3. Graphics Output
   Server app ─> update.c
             ─> codec/ (encode)
             ─> rdp.c ─> Client
```

## Build Dependencies

```
winpr (no dependencies except system libs)
  │
  ├─> libfreerdp (depends on winpr)
  │     │
  │     ├─> channels (depends on libfreerdp, winpr)
  │     │
  │     ├─> client/common (depends on libfreerdp)
  │     │     │
  │     │     └─> client apps (depend on client/common)
  │     │
  │     └─> server/common (depends on libfreerdp)
  │           │
  │           └─> server apps (depend on server/common)
  │
  ├─> rdtk (depends on winpr)
  │
  └─> uwac (depends on winpr, Wayland)
```

## Key Interfaces

### Client Entry Point

```c
#include <freerdp/freerdp.h>

freerdp* instance = freerdp_new();
instance->PreConnect = my_pre_connect;
instance->PostConnect = my_post_connect;
instance->ContextNew = my_context_new;
// ... set callbacks
freerdp_connect(instance);
```

### Server Entry Point

```c
#include <freerdp/listener.h>

freerdp_listener* listener = freerdp_listener_new();
listener->PeerAccepted = my_peer_accepted;
freerdp_listener_open(listener, bind_address, port);
```

### Channel Plugin Entry Point

```c
FREERDP_ENTRY_POINT(UINT VCAPITYPE VirtualChannelEntry(PCHANNEL_ENTRY_POINTS pEntryPoints))
{
    // Register channel
}
```

## Platform Support

| Platform | Client | Server | Notes |
|----------|:------:|:------:|-------|
| Linux (X11) | ✓ | ✓ | Primary platform |
| Linux (Wayland) | ✓ | - | Via SDL or native |
| Windows | ✓ | ✓ | Native support |
| macOS | ✓ | ✓ | Cocoa/Metal |
| iOS | ✓ | - | Touch optimized |
| Android | ✓ | - | JNI bindings |
| FreeBSD | ✓ | ✓ | Community maintained |

## Further Reading

- [libfreerdp-architecture.md](libfreerdp-architecture.md) - Core library details
- [winpr-architecture.md](winpr-architecture.md) - Portable runtime details
- [channels-architecture.md](channels-architecture.md) - Virtual channels details
- [wlog.md](wlog.md) - Logging system documentation
- [PrintFormatSpecifiers.md](PrintFormatSpecifiers.md) - Printf format guidelines
