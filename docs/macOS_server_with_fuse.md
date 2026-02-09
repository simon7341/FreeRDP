Below is a **requirements / prompt document** you can directly feed into an AI model to generate architecture, code skeletons, and implementation details.

---

# FreeRDP-based RDP Server App (macOS-first, Windows-extensible) — Requirements

## 1. Purpose

Develop a **production-grade RDP server application** on **macOS**, implemented on top of **FreeRDP server libraries**, that supports:

1. Standard RDP remote desktop session
2. **Drive redirection (RDPDR)** implemented as a **mounted filesystem** on the server side
3. A clean architecture so the same codebase can later support **Windows** with minimal redesign

The initial goal is **macOS server**. The future goal is **Windows server**.

---

## 2. High-Level Features

### 2.1 RDP Server Core

* Accept RDP connections from standard clients (mstsc, FreeRDP, etc.)
* Support authentication (at least basic username/password in v1)
* Support multiple sessions (design for it; v1 may run single-session)

### 2.2 Drive Redirection (RDPDR)

* Server must accept redirected client drives via **RDPDR**
* Server must expose redirected drives as a **local mount** on macOS using **macFUSE**
* Redirected drives appear as:

  * `/Volumes/tsclient/<DriveName>/...`
  * Example: `/Volumes/tsclient/C/Users/...`

### 2.3 Windows Extensibility

The design must allow a Windows build in the future where:

* the same drive redirection backend is reused
* only the filesystem frontend changes:

  * macOS: macFUSE
  * Windows: WinFsp

---

## 3. Non-Goals (v1)

* Implementing literal `\\tsclient\` namespace (Windows-only kernel feature)
* Printer redirection
* Smart card redirection
* Audio redirection
* Clipboard HTML/image support (not part of this requirement)
* GPU acceleration
* Full multi-user TS server replacement

---

## 4. Architectural Requirements

## 4.1 Strict Layering

The application must be split into these layers:

### Layer A — `RdpServerCore`

* Owns FreeRDP server session lifecycle
* Manages client connections
* Provides events for:

  * session connected/disconnected
  * channel availability
  * RDPDR device list updates
  * RDPDR IO completion messages

### Layer B — `RdpdrBackend` (platform-independent)

A pure logic layer that:

* maintains device table (drive name → device id)
* maintains pending request table (CompletionId → future/event)
* provides synchronous APIs:

```text
SendCreate()
SendRead()
SendWrite()
SendQueryInfo()
SendSetInfo()
SendQueryDirectory()
SendQueryVolumeInfo()
SendClose()
```

* performs chunking for large reads/writes
* performs error mapping into a platform-neutral error type

### Layer C — `VirtualFileSystemFrontend` (platform-specific)

This layer provides a mounted filesystem.

* macOS: macFUSE
* Windows future: WinFsp

This layer:

* parses paths (e.g. `/Volumes/tsclient/C/foo.txt`)
* maps them into `{DeviceId, RemotePath}`
* calls `RdpdrBackend` APIs
* translates errors to OS error codes

### Layer D — `AppHost`

* CLI entry point or GUI wrapper
* config loading
* logging
* service lifecycle

---

## 4.2 Platform Abstraction Requirements

Define explicit interfaces so the core is portable:

### 4.2.1 `IFileSystemFrontend`

```text
StartMount()
StopMount()
UpdateDriveList(drives)
```

### 4.2.2 `IRdpdrTransport`

```text
SendDeviceIoRequest(packetBytes)
RegisterCompletionCallback(fn)
```

### 4.2.3 `ISessionLifecycle`

```text
OnConnected()
OnDisconnected()
```

The macOS and Windows implementations must be isolated behind these interfaces.

---

## 5. Drive Redirection Functional Requirements

## 5.1 Device Discovery

* On client connect, wait for RDPDR device announce
* For each filesystem device:

  * store `DeviceId`, `DosName`
  * expose it as a top-level directory in the mount

## 5.2 Path Mapping Rules

* Mount root represents the “tsclient root”
* Each redirected drive is a directory under root
* Example mapping:

```text
/Volumes/tsclient/C/abc.txt
  -> Device = "C"
  -> Remote path = "\abc.txt"
```

## 5.3 Required Filesystem Operations

The filesystem frontend must support at minimum:

* directory listing
* open/create
* close
* read
* write
* rename
* delete file
* delete directory
* create directory
* query volume free space
* query file metadata (size, timestamps, attributes)

## 5.4 Correctness Requirements

* Multiple concurrent file handles must be supported
* Directory enumeration must be stable for Finder/Explorer behavior
* Reads/writes must be offset-based and support large transfers (chunking)

## 5.5 Performance Requirements

* Implement metadata caching (short TTL) to avoid Finder hammering
* Implement directory listing caching per handle or per directory (short TTL)
* Support multiple outstanding IRPs concurrently

---

## 6. RDPDR Protocol Requirements

## 6.1 Request/Completion Model

* Every outgoing IRP must include a unique CompletionId
* The backend must support async completions arriving out-of-order
* Pending requests must support:

  * timeout
  * cancellation on session disconnect

## 6.2 IRP Coverage (v1)

Must support:

* IRP_MJ_CREATE
* IRP_MJ_CLOSE
* IRP_MJ_READ
* IRP_MJ_WRITE
* IRP_MJ_QUERY_INFORMATION
* IRP_MJ_SET_INFORMATION
* IRP_MJ_QUERY_VOLUME_INFORMATION
* IRP_MJ_DIRECTORY_CONTROL / IRP_MN_QUERY_DIRECTORY

Optional (phase 2):

* IRP_MJ_LOCK_CONTROL
* flush semantics

---

## 7. Error Handling Requirements

* No crashes on malformed RDPDR responses
* All filesystem operations must return valid OS error codes
* Session disconnect must:

  * fail all pending requests
  * unmount filesystem cleanly (or show empty root)

Error mapping must be implemented:

* NTSTATUS-like values → platform-neutral → POSIX errno (macOS) / Win32 (Windows)

---

## 8. Logging Requirements

* Provide structured logs with:

  * timestamp
  * thread id
  * module
  * severity
  * message
* Log RDPDR device list changes
* Log every IRP request/response at debug level (toggleable)
* Log timeouts and slow operations

---

## 9. Threading Requirements

* FreeRDP network/session thread must never be blocked by filesystem callbacks
* Filesystem callbacks may block waiting for RDPDR completions
* Pending request table must be thread-safe
* Use a clear concurrency model:

  * one RDP thread for receiving
  * a worker pool (FUSE threads) for filesystem operations

---

## 10. Security Requirements

* Mount point must be accessible only to the server process user by default
* Do not allow path traversal / invalid paths
* Enforce session boundaries: drives belong to the connected session only
* Future: optional policy control (allow/deny drive redirection)

---

## 11. Build / Project Requirements

* Language: C++17 or newer

* macOS build system: CMake

* Must build on:

  * macOS (primary)
  * Windows (future target; architecture must anticipate it)

* External dependencies:

  * FreeRDP (server libraries)
  * macFUSE (macOS)
  * (future) WinFsp (Windows)

---

## 12. Deliverables (v1)

1. A macOS executable RDP server app
2. A mounted filesystem exposing redirected client drives
3. Clean module separation:

   * core
   * rdpdr backend
   * macFUSE frontend
4. Minimal documentation explaining:

   * module layout
   * how to add Windows WinFsp frontend later

---

## 13. Acceptance Criteria

The implementation is accepted when:

1. A Windows client (mstsc) connects to the macOS server
2. The Windows client redirects drive C
3. On the macOS server, the mount appears:

   * `/Volumes/tsclient/C/...`
4. Finder can:

   * browse directories
   * open files
   * copy a file from redirected drive to local disk
   * copy a file from local disk to redirected drive
   * rename and delete files
5. Disconnecting the client cleanly unmounts or invalidates the mount without hanging

---

## 14. Prompt Usage Guidance (for AI model)

When generating code or architecture:

* prioritize clean interfaces and portability
* avoid embedding macFUSE logic inside RDPDR backend
* keep FreeRDP modifications minimal
* treat RDPDR as an async transport requiring a pending-request mechanism
* implement v1 operations first (read-only browsing), then write support

---

