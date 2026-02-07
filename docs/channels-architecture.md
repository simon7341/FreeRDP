# Channels Architecture Overview

FreeRDP implements RDP virtual channels as plugins in the `channels/` directory. Virtual channels extend RDP functionality by allowing data exchange between client and server for features like clipboard sharing, audio, drive redirection, and more.

## Channel Types

- **Static Virtual Channels (SVC)**: Established during connection, fixed set of channels
- **Dynamic Virtual Channels (DVC)**: Created on-demand over the DRDYNVC channel

## Directory Structure

Each channel typically has:
- `client/` - Client-side plugin implementation
- `server/` - Server-side implementation (if applicable)
- `common/` - Shared code between client and server (some channels)

## Channel Reference

### Core Infrastructure

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **drdynvc** | Dynamic Virtual Channel multiplexer - enables all DVC-based channels | ✓ | ✓ |

### Clipboard & Input

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **cliprdr** | Clipboard redirection - copy/paste between local and remote | ✓ | ✓ |
| **ainput** | Advanced Input - extended input events (touch, pen) | ✓ | ✓ |
| **rdpei** | Extended Input - multitouch support | ✓ | ✓ |
| **rdpemsc** | Mouse Cursor - server-side cursor rendering | - | ✓ |

### Audio

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **rdpsnd** | Audio Output - sound playback from server to client | ✓ | ✓ |
| **audin** | Audio Input - microphone redirection to server | ✓ | ✓ |

### Graphics & Display

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **rdpgfx** | Graphics Pipeline - modern graphics remoting (GFX) | ✓ | ✓ |
| **disp** | Display Control - dynamic resolution changes | ✓ | ✓ |
| **geometry** | Geometry Tracking - window geometry for video optimization | ✓ | - |
| **video** | Video Optimized Remoting - H.264 video streaming | ✓ | - |
| **gfxredir** | Graphics Redirection - GPU acceleration | - | ✓ |

### Device Redirection

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **rdpdr** | Device Redirection - base channel for device plugins | ✓ | ✓ |
| **drive** | Drive/File System redirection | ✓ | - |
| **printer** | Printer redirection | ✓ | - |
| **smartcard** | Smart card redirection | ✓ | - |
| **serial** | Serial port redirection | ✓ | - |
| **parallel** | Parallel port redirection | ✓ | - |

### USB & Camera

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **urbdrc** | USB Redirection - RemoteFX USB | ✓ | - |
| **rdpecam** | Camera/Webcam redirection | ✓ | ✓ |

### Remote Applications

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **rail** | Remote Applications (RemoteApp) - seamless windows | ✓ | ✓ |
| **encomsp** | Multiparty - conferencing/application sharing | ✓ | ✓ |
| **remdesk** | Remote Assistance - remote help sessions | ✓ | ✓ |

### Authentication & Security

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **rdpear** | Authentication Redirection - credential forwarding | ✓ | - |

### Location & Telemetry

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **location** | Location/GPS redirection | ✓ | ✓ |
| **telemetry** | Telemetry data collection | - | ✓ |

### Networking & Tunneling

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **rdp2tcp** | TCP tunneling over RDP | ✓ | - |
| **sshagent** | SSH Agent forwarding | ✓ | - |

### Miscellaneous

| Channel | Description | Client | Server |
|---------|-------------|:------:|:------:|
| **echo** | Echo test channel - for testing/debugging | ✓ | ✓ |
| **tsmf** | Multimedia Redirection (legacy) - video/audio streaming | ✓ | - |

## Channel Implementation Details

### Static Channels

Static channels are defined at connection time. Key static channels:
- `cliprdr` - Clipboard
- `rdpsnd` - Audio output
- `rdpdr` - Device redirection base

### Dynamic Channels (via DRDYNVC)

Dynamic channels are created on-demand through the DRDYNVC multiplexer:
- `rdpgfx` - Graphics pipeline
- `rdpei` - Extended input
- `audin` - Audio input
- `video` - Video streaming
- `geometry` - Window geometry
- `disp` - Display control

### Device Redirection Hierarchy

The `rdpdr` channel serves as a base for device-specific channels:

```
rdpdr (Device Redirection)
├── drive (File System)
├── printer (Printers)
├── smartcard (Smart Cards)
├── serial (Serial Ports)
└── parallel (Parallel Ports)
```

### Audio Subsystem

Audio channels support multiple backends:

**rdpsnd (Output):**
- PulseAudio (`pulse/`)
- ALSA (`alsa/`)
- macOS (`mac/`)
- iOS (`ios/`)
- OpenSL ES (`opensles/` - Android)
- OSS (`oss/`)
- sndio (`sndio/` - OpenBSD)
- Windows Multimedia (`winmm/`)

**audin (Input):**
- Same backend support as rdpsnd

### Graphics Pipeline (RDPGFX)

The `rdpgfx` channel implements modern RDP graphics:
- Progressive codec support
- H.264/AVC encoding
- Surface management
- Frame markers

## Creating a New Channel

1. Create directory under `channels/<name>/`
2. Add `client/` and/or `server/` subdirectories
3. Implement main entry point in `<name>_main.c`
4. Register with channel manager
5. Add to `channels/CMakeLists.txt`

## Key Source Files

For each channel, the typical structure is:
- `<name>_main.c` - Entry point, channel lifecycle
- `<name>_main.h` - Internal definitions
- Additional files for complex channels (e.g., `cliprdr_format.c`)

## Related Headers

Channel APIs are defined in `include/freerdp/channels/`:
- `channels.h` - Channel manager API
- `cliprdr.h` - Clipboard channel
- `rdpgfx.h` - Graphics pipeline
- `rdpsnd.h` - Audio output
- `audin.h` - Audio input
- `rdpdr.h` - Device redirection
- etc.
