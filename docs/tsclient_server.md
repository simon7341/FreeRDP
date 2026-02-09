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

## Windows WinFsp Frontend

The Windows WinFsp frontend lives in `server/tsclient/winfsp_frontend.*`. It is wired into
`tsclientd` on Windows builds and gated by `-DWITH_WINFSP_SERVER=ON`. The current implementation
implements create/open/read/write/readdir/statfs and maps `\C\path` to the RDPDR drive table.
It supports mounting as a drive letter or a directory path (directory mounts are created if needed).

## Build

```
cmake -DWITH_TSFUSE_SERVER=ON -DWITH_MACFUSE=OFF ..
```

Enable macFUSE integration by providing macFUSE headers and building with `-DWITH_MACFUSE=ON`.

For Windows (WinFsp):
```
cmake -DWITH_TSFUSE_SERVER=ON -DWITH_WINFSP_SERVER=ON ..
```

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

On Windows, `--mount-root` accepts either a drive letter (`T:`) or a directory path
(e.g. `C:\mount\tsclient`). Drive-letter mounts are normalized to `X:` form.

## Current Limitations

- Basic metadata and volume info are served via RDPDR query calls; cache TTL may surface brief
  staleness for out-of-band changes until the cache expires.
- Windows WinFsp frontend has not been validated on a real Windows host yet.
- The following operations remain unimplemented: chmod/chown, locks, ACLs.
- Symbolic link creation is mapped to a hard link via RDPDR `FileLinkInformation` on redirected
  drives (true Windows symlinks are not yet supported).
- Single-session only; additional connections are rejected.
