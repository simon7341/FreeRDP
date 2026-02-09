# tsclient RDP Server (macOS-first)

This is a macOS-first RDP server layout that matches `docs/macOS_server_with_fuse.md`.
The current implementation wires FreeRDP server lifecycle, RDPDR server callbacks, and a macFUSE
frontend for basic filesystem operations. It still uses the built-in FreeRDP server-side RDPDR
helpers (not a custom wire packer) and implements basic metadata and volume queries.

## Module Layout

- `server/tsclient/rdp_server_core.*`
  - Session lifecycle entry point for FreeRDP server wiring.
  - Owns connection lifecycle and coordinates mount start/stop.
- `server/tsclient/rdpdr_backend.*`
  - Platform-independent request table and chunking logic.
  - Maintains drive table and pending IRPs.
- `server/tsclient/vfs_frontend.*`
  - macOS filesystem frontend (macFUSE integration).
  - Directory listing + metadata caches with short TTL.
- `server/tsclient/path_mapper.*`
  - Maps `/Volumes/tsclient/<Drive>/...` into `{device_id, remote_path}`.
- `server/tsclient/tsclientd.cpp`
  - CLI app host.

## How To Add Windows WinFsp Frontend Later

1. Create a new frontend class (e.g., `WinFspFrontend`) implementing `IFileSystemFrontend`.
2. Reuse `RdpdrBackend` unchanged for device tables, pending IRPs, and chunked reads/writes.
3. Add a Windows-only CMake target that links against WinFsp and includes the new frontend.
4. Update `server/CMakeLists.txt` with a `WITH_WINFSP_SERVER` option guarded by `WIN32`.

## Build

```
cmake -DWITH_TSFUSE_SERVER=ON -DWITH_MACFUSE=OFF ..
```

Enable macFUSE integration by providing macFUSE headers and building with `-DWITH_MACFUSE=ON`.

## macFUSE Enablement Checklist

- Install macFUSE (headers + library).
- Build with:
```
cmake -DWITH_TSFUSE_SERVER=ON -DWITH_MACFUSE=ON ..
```
- Ensure the mount root exists and is writable by the server user (default is `/Volumes/tsclient`).
  - `/Volumes` may require elevated privileges; use `--mount-root` to choose a user-writable path.

## Run

```
./build/server/tsclient/tsclientd --mount-root /tmp/tsclient
```

## Current Limitations

- Basic metadata and volume info are served via RDPDR query calls; cache TTL may surface brief
  staleness after write/rename/delete until the cache expires.
- Single-session only; additional connections are rejected.
