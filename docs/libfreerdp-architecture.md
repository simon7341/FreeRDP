# libfreerdp Architecture Overview

This document describes the subdirectory structure of `libfreerdp/`, the core RDP protocol implementation library.

## core/ - RDP Protocol Engine (51 files)

The heart of the RDP implementation, handling the protocol state machine and connection lifecycle:

- **Connection & Session**: `connection.c`, `nego.c`, `mcs.c`, `gcc.c`, `activation.c`, `state.c`
- **Authentication**: `nla.c`, `credssp_auth.c`, `aad.c` (Azure AD), `license.c`, `smartcardlogon.c`, `rdstls.c`
- **Transport Layer**: `transport.c`, `tcp.c`, `tpkt.c`, `tpdu.c`, `fastpath.c`, `multitransport.c`
- **Protocol Core**: `rdp.c`, `security.c`, `capabilities.c`, `info.c`, `settings.c`
- **Graphics/Input**: `orders.c`, `update.c`, `input.c`, `graphics.c`, `surface.c`, `window.c`
- **Channels**: `channels.c` - virtual channel management
- **Client/Server**: `client.c`, `server.c`, `peer.c`, `listener.c`
- **Error Handling**: `errbase.c`, `errconnect.c`, `errinfo.c`
- **Utilities**: `redirection.c`, `proxy.c`, `heartbeat.c`, `autodetect.c`, `timer.c`, `timezone.c`, `metrics.c`

## codec/ - Image & Audio Codecs (32 files)

Encoding/decoding for graphics and audio:

- **Bitmap Compression**: `bitmap.c`, `interleaved.c`, `planar.c`
- **RemoteFX (RFX)**: `rfx.c`, `rfx_decode.c`, `rfx_encode.c`, `rfx_dwt.c`, `rfx_quantization.c`, `rfx_rlgr.c`
- **NSC**: `nsc.c`, `nsc_encode.c`
- **H.264**: `h264.c`, `h264_ffmpeg.c`, `h264_openh264.c`, `h264_mf.c` (Media Foundation), `h264_mediacodec.c` (Android)
- **Progressive Codec**: `progressive.c`
- **Other Graphics**: `clear.c`, `zgfx.c`, `jpeg.c`, `yuv.c`, `color.c`, `region.c`
- **Compression**: `bulk.c`, `mppc.c`, `ncrush.c`, `xcrush.c`
- **Audio DSP**: `dsp.c`, `dsp_ffmpeg.c`, `dsp_fdk_aac.c`, `audio.c`

## crypto/ - Cryptography & Certificates (14 files)

Security primitives and certificate management:

- **Encoding**: `base64.c`, `ber.c`, `der.c`, `er.c`, `per.c`
- **Certificates**: `certificate.c`, `certificate_data.c`, `certificate_store.c`, `cert_common.c`, `x509_utils.c`
- **Keys & TLS**: `privatekey.c`, `tls.c`, `crypto.c`
- **Compatibility**: `opensslcompat.c`

## gdi/ - Graphics Device Interface (13 files)

2D graphics rendering abstraction:

- **Core**: `gdi.c`, `dc.c` (device context), `graphics.c`
- **Drawing**: `drawing.c`, `bitmap.c`, `line.c`, `shape.c`, `brush.c`, `pen.c`
- **Regions**: `region.c`, `clipping.c`
- **Extensions**: `gfx.c` (RDPGFX support), `video.c`

## cache/ - Protocol Caches (9 files)

Client-side caching for performance:

- `cache.c` - cache manager
- `bitmap.c`, `brush.c`, `glyph.c`, `pointer.c`, `palette.c`
- `offscreen.c`, `nine_grid.c`, `persistent.c`

## primitives/ - SIMD-Optimized Operations (11 files)

Low-level graphics operations with CPU-specific optimizations (SSE, NEON):

- `primitives.c` - runtime CPU detection and dispatch
- `prim_YUV.c`, `prim_YCoCg.c` - color space conversion
- `prim_colors.c`, `prim_copy.c`, `prim_set.c`
- `prim_add.c`, `prim_shift.c`, `prim_sign.c`
- `prim_alphaComp.c`, `prim_andor.c`

## utils/ - Utility Functions (17 files)

Shared helper code:

- **Channel Helpers**: `cliprdr_utils.c`, `rdpdr_utils.c`, `drdynvc.c`, `gfx.c`
- **Smartcard**: `smartcard_call.c`, `smartcard_operations.c`, `smartcard_pack.c`
- **Networking**: `http.c`, `encoded_types.c`
- **Debugging**: `profiler.c`, `stopwatch.c`, `pcap.c`, `ringbuffer.c`
- **Misc**: `helpers.c`, `string.c`, `signal.c`, `passphrase.c`

## locale/ - Keyboard & Locale (8 files)

Keyboard layout mapping across platforms:

- `keyboard.c`, `keyboard_layout.c`, `xkb_layout_ids.c`
- Platform-specific: `keyboard_x11.c`, `keyboard_xkbfile.c`, `keyboard_apple.c`, `keyboard_sun.c`
- `locale.c`

## common/ - Shared Settings (5 files)

Configuration and add-in management:

- `settings.c`, `settings_getters.c`, `settings_str.c`
- `addin.c` - plugin loading
- `assistance.c` - Remote Assistance support

## emu/ - Emulation

Smartcard emulation support (header-only, implementation elsewhere).
