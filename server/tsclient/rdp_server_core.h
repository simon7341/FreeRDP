#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include <freerdp/listener.h>

#include "rdpdr_backend.h"
#include "rdpdr_transport.h"

namespace tsclient
{

struct ServerConfig
{
	std::string bind_address = "0.0.0.0";
	std::uint16_t port = 3389;
	std::string cert_path = "server.crt";
	std::string key_path = "server.key";
	bool local_only = false;
};

class RdpServerCore : public ISessionLifecycle
{
  public:
	explicit RdpServerCore(RdpdrBackend* backend);
	~RdpServerCore();

	bool Start(const ServerConfig& config, IFileSystemFrontend* fs_frontend);
	void Stop();

	void OnConnected() override;
	void OnDisconnected() override;

	void NotifyDriveList(const std::vector<DriveInfo>& drives);
	RdpdrBackend* Backend() const { return backend_; }

  private:
	static BOOL PeerAccepted(freerdp_listener* instance, freerdp_peer* client);
	static DWORD WINAPI PeerMainLoop(LPVOID arg);
	static void ServerMainLoop(RdpServerCore* server);

	RdpdrBackend* backend_ = nullptr;
	IFileSystemFrontend* fs_frontend_ = nullptr;
	ServerConfig config_;

	freerdp_listener* listener_ = nullptr;
	HANDLE listener_thread_ = nullptr;
	std::atomic<bool> running_{ false };
	std::atomic<bool> session_active_{ false };
};

} // namespace tsclient
