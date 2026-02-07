# WinPR Architecture Overview

WinPR (Windows Portable Runtime) is a cross-platform abstraction layer that provides Windows API equivalents for non-Windows platforms. It allows FreeRDP to use familiar Windows APIs while remaining portable across Linux, macOS, iOS, Android, and other systems.

## Core Runtime

### crt/ - C Runtime Extensions
Standard C library extensions and portability helpers:
- `string.c` - string manipulation functions
- `memory.c` - memory allocation wrappers
- `conversion.c` - type conversions
- `unicode.c`, `unicode_builtin.c`, `unicode_icu.c`, `unicode_android.c` - Unicode/UTF conversion
- `alignment.c` - aligned memory allocation
- `buffer.c`, `assert.c`

### memory/ - Memory Management
- `memory.c` - heap allocation functions (HeapAlloc, HeapFree equivalents)

### handle/ - Handle Management
- `handle.c` - generic handle infrastructure for WinPR objects
- `nonehandle.c` - null handle implementation

### error/ - Error Handling
- `error.c` - GetLastError/SetLastError implementation

## Threading & Synchronization

### thread/ - Thread Management
- `thread.c` - CreateThread, thread lifecycle management
- `process.c` - process creation and management
- `processor.c` - processor information
- `tls.c` - Thread Local Storage
- `apc.c` - Asynchronous Procedure Calls
- `argv.c` - command-line argument parsing

### synch/ - Synchronization Primitives
- `mutex.c` - mutexes (CreateMutex, etc.)
- `semaphore.c` - semaphores
- `event.c` - events (CreateEvent, SetEvent, WaitForSingleObject)
- `critical.c` - critical sections
- `barrier.c` - synchronization barriers
- `timer.c` - waitable timers
- `sleep.c` - Sleep functions
- `init.c` - one-time initialization
- `address.c` - address-based waiting
- `pollset.c` - poll/select abstraction

### interlocked/ - Atomic Operations
- `interlocked.c` - InterlockedIncrement, InterlockedCompareExchange, etc.

### pool/ - Thread Pool
Windows Thread Pool API implementation:
- `pool.c` - thread pool management
- `work.c` - work items
- `timer.c` - timer callbacks
- `io.c` - I/O completion callbacks
- `callback.c`, `callback_cleanup.c` - callback management
- `cleanup_group.c` - cleanup groups
- `synch.c` - synchronization callbacks

## Cryptography & Security

### crypto/ - Cryptographic Primitives
Low-level crypto operations:
- `crypto.c` - general crypto utilities
- `hash.c` - hash algorithms
- `cipher.c` - symmetric encryption
- `cert.c` - certificate handling
- `rand.c` - random number generation
- `md4.c`, `md5.c` - MD4/MD5 hash implementations
- `hmac_md5.c` - HMAC-MD5
- `rc4.c` - RC4 stream cipher

### bcrypt/ - BCrypt API
- `bcrypt.c` - Windows BCrypt API implementation

### ncrypt/ - NCrypt API
- `ncrypt.c` - Windows NCrypt API (key storage)
- `ncrypt_pkcs11.c` - PKCS#11 backend

### security/ - Security API
- `security.c` - security descriptor and token functions

### sspi/ - Security Support Provider Interface
Authentication framework (NTLM, Kerberos, etc.):
- `sspi.c` - SSPI dispatcher
- `sspi_winpr.c` - WinPR SSPI implementation
- `sspi_gss.c` - GSS-API integration
- `sspi_export.c` - exported functions

### sspicli/ - SSPI Client
- `sspicli.c` - client-side SSPI functions

### credentials/ - Credential Management
- `credentials.c` - credential storage and retrieval

## I/O & File System

### file/ - File Operations
- `file.c` - CreateFile, ReadFile, WriteFile equivalents
- `generic.c` - generic file operations
- `namedPipeClient.c` - named pipe client
- `pattern.c` - file pattern matching (wildcards)

### pipe/ - Named Pipes
- `pipe.c` - CreateNamedPipe, pipe operations

### io/ - I/O Operations
- `io.c` - overlapped I/O, completion ports
- `device.c` - device I/O control

### comm/ - Serial Communications
Serial port support:
- `comm.c` - COM port abstraction
- `comm_io.c` - serial I/O operations
- `comm_ioctl.c` - serial IOCTLs
- `comm_serial_sys.c`, `comm_sercx_sys.c`, `comm_sercx2_sys.c` - driver implementations

### path/ - Path Manipulation
- `path.c` - path utilities (SHGetFolderPath equivalents)
- `shell.c` - shell folder paths

## Networking

### winsock/ - Windows Sockets
- `winsock.c` - Winsock API abstraction

## System Information

### sysinfo/ - System Information
- `sysinfo.c` - GetSystemInfo, processor/memory info, version detection

### environment/ - Environment Variables
- `environment.c` - GetEnvironmentVariable, SetEnvironmentVariable

### timezone/ - Timezone Support
- `timezone.c` - timezone conversion
- `WindowsZones.c` - Windows timezone database
- `TimeZoneNameMapUtils.c`, `TimeZoneIanaAbbrevMap.c` - timezone name mapping

### registry/ - Registry Access
- `registry.c` - RegOpenKey, RegQueryValue equivalents
- `registry_reg.c` - .reg file parsing

## Input

### input/ - Keyboard/Mouse Input
- `scancode.c` - keyboard scancode handling
- `virtualkey.c` - virtual key codes
- `keycode.c` - keycode conversion

## Smart Card

### smartcard/ - Smart Card API
PC/SC smart card abstraction:
- `smartcard.c` - SCard API dispatcher
- `smartcard_pcsc.c` - PC/SC backend (Linux/macOS)
- `smartcard_windows.c` - Windows backend
- `smartcard_inspect.c` - debugging/inspection

## IPC & RPC

### rpc/ - Remote Procedure Call
- `rpc.c` - RPC runtime support

### wtsapi/ - Windows Terminal Services API
- `wtsapi.c` - WTS API implementation
- `wtsapi_win32.c` - Windows-specific implementation

## Utilities

### library/ - Dynamic Library Loading
- `library.c` - LoadLibrary, GetProcAddress equivalents

### clipboard/ - Clipboard
- `clipboard.c` - clipboard format handling
- `synthetic.c`, `synthetic_file.c` - synthetic clipboard formats

### shell/ - Shell Operations
- `shell.c` - shell utility functions

### nt/ - NT Internals
- `nt.c` - low-level NT functions
- `ntstatus.c` - NTSTATUS codes

### dsparse/ - Directory Services
- `dsparse.c` - DS name parsing

### utils/ - General Utilities
- `stream.c` - binary stream reading/writing (wStream)
- `cmdline.c` - command-line parsing
- `ini.c` - INI file parsing
- `image.c` - image utilities
- `debug.c` - debugging helpers
- `print.c` - printing utilities
- `ssl.c` - SSL/TLS utilities
- `sam.c` - SAM file parsing
- `ntlm.c` - NTLM utilities
- `android.c` - Android-specific utilities

## Key Public Headers

Located in `winpr/include/winpr/`:

| Header | Purpose |
|--------|---------|
| `winpr.h` | Main WinPR header |
| `stream.h` | wStream binary stream API |
| `thread.h` | Thread management |
| `synch.h` | Synchronization primitives |
| `sspi.h` | SSPI authentication |
| `crypto.h` | Cryptography |
| `file.h` | File operations |
| `path.h` | Path utilities |
| `wlog.h` | Logging framework |
| `collections.h` | Data structures (ArrayList, HashTable, etc.) |
| `cmdline.h` | Command-line parsing |
| `smartcard.h` | Smart card API |
| `clipboard.h` | Clipboard handling |
| `winsock.h` | Socket abstraction |
| `registry.h` | Registry access |
| `input.h` | Input handling |
