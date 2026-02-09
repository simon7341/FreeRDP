#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace tsclient
{

enum class RdpdrError
{
	Ok = 0,
	Timeout,
	Cancelled,
	NotConnected,
	InvalidDevice,
	TransportError,
	ProtocolError,
	NotSupported,
	AccessDenied,
	NotFound,
	IoError,
	Busy,
};

struct RdpdrResult
{
	RdpdrError error = RdpdrError::Ok;
	std::vector<std::uint8_t> payload;
};

struct DriveInfo
{
	std::uint32_t device_id = 0;
	std::string dos_name;
};

class IRdpdrTransport
{
  public:
	using CompletionCallback = std::function<void(std::uint32_t completion_id, RdpdrError error,
	                                              std::vector<std::uint8_t> payload)>;

	virtual ~IRdpdrTransport() = default;
	virtual bool SendDeviceIoRequest(const std::vector<std::uint8_t>& packet_bytes) = 0;
	virtual void RegisterCompletionCallback(CompletionCallback cb) = 0;
};

class IFileSystemFrontend
{
  public:
	virtual ~IFileSystemFrontend() = default;
	virtual bool StartMount() = 0;
	virtual void StopMount() = 0;
	virtual void UpdateDriveList(const std::vector<DriveInfo>& drives) = 0;
};

class ISessionLifecycle
{
  public:
	virtual ~ISessionLifecycle() = default;
	virtual void OnConnected() = 0;
	virtual void OnDisconnected() = 0;
};

} // namespace tsclient
