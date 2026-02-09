#include "rdp_server_core.h"

#include <cerrno>

#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/peer.h>
#include <freerdp/settings.h>
#include <freerdp/channels/wtsvc.h>
#include <freerdp/server/rdpdr.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/path.h>
#include <winpr/crt.h>

#include <freerdp/log.h>

#define TAG SERVER_TAG("tsclient-core")

namespace tsclient
{

struct TsclientPeerContext
{
	rdpContext _p;
	HANDLE vcm = nullptr;
	RdpdrServerContext* rdpdr = nullptr;
	RdpServerCore* server = nullptr;
};

typedef struct TsclientPeerContext TsclientPeerContext;

static void tsclient_peer_context_free(freerdp_peer* client, rdpContext* ctx)
{
	auto* context = reinterpret_cast<TsclientPeerContext*>(ctx);
	WINPR_UNUSED(client);
	if (!context)
		return;

	if (context->server)
		context->server->Backend()->DetachServerContext();
	if (context->rdpdr)
	{
		context->rdpdr->Stop(context->rdpdr);
		rdpdr_server_context_free(context->rdpdr);
		context->rdpdr = nullptr;
	}
	if (context->vcm)
	{
		WTSCloseServer(context->vcm);
		context->vcm = nullptr;
	}
}

static BOOL tsclient_peer_context_new(freerdp_peer* client, rdpContext* ctx)
{
	auto* context = reinterpret_cast<TsclientPeerContext*>(ctx);
	WINPR_ASSERT(client);
	WINPR_ASSERT(context);
	context->server = static_cast<RdpServerCore*>(client->ContextExtra);
	context->vcm = WTSOpenServerA((LPSTR)client->context);
	if (!context->vcm || context->vcm == INVALID_HANDLE_VALUE)
		return FALSE;

	context->rdpdr = rdpdr_server_context_new(context->vcm);
	if (!context->rdpdr)
		return FALSE;

	return TRUE;
}

static BOOL tsclient_peer_init(freerdp_peer* client)
{
	WINPR_ASSERT(client);
	client->ContextSize = sizeof(TsclientPeerContext);
	client->ContextNew = tsclient_peer_context_new;
	client->ContextFree = tsclient_peer_context_free;
	return freerdp_peer_context_new(client);
}

static BOOL tsclient_peer_post_connect(freerdp_peer* client)
{
	auto* context = reinterpret_cast<TsclientPeerContext*>(client->context);
	if (!context || !context->server || !context->rdpdr)
		return FALSE;

	context->server->OnConnected();
	context->server->Backend()->AttachServerContext(context->rdpdr);
	context->server->Backend()->SetDriveListCallback(
	    [server = context->server](const std::vector<DriveInfo>& drives) {
		    server->NotifyDriveList(drives);
	    });

	if (context->rdpdr->Start(context->rdpdr) != CHANNEL_RC_OK)
		return FALSE;

	return TRUE;
}

static BOOL tsclient_peer_activate(freerdp_peer* client)
{
	WINPR_UNUSED(client);
	return TRUE;
}

RdpServerCore::RdpServerCore(RdpdrBackend* backend) : backend_(backend) {}

RdpServerCore::~RdpServerCore()
{
	Stop();
}

bool RdpServerCore::Start(const ServerConfig& config, IFileSystemFrontend* fs_frontend)
{
	if (running_)
		return true;
	config_ = config;
	fs_frontend_ = fs_frontend;

	listener_ = freerdp_listener_new();
	if (!listener_)
		return false;
	listener_->info = this;
	listener_->PeerAccepted = PeerAccepted;

	if (!listener_->Open(listener_, config_.local_only ? "127.0.0.1" : config_.bind_address.c_str(),
	                     config_.port))
	{
		freerdp_listener_free(listener_);
		listener_ = nullptr;
		return false;
	}

	running_ = true;
	listener_thread_ = CreateThread(NULL, 0, [](LPVOID arg) -> DWORD {
		ServerMainLoop(static_cast<RdpServerCore*>(arg));
		return 0;
	}, this, 0, NULL);

	WLog_Print(WLog_Get(TAG), WLOG_INFO, "RDP server listening on %s:%u",
	           config_.bind_address.c_str(), config_.port);
	return listener_thread_ != nullptr;
}

void RdpServerCore::Stop()
{
	if (!running_)
		return;
	running_ = false;
	WLog_Print(WLog_Get(TAG), WLOG_INFO, "Stopping listener.");
	if (listener_)
		listener_->Close(listener_);
	if (listener_thread_)
	{
		WaitForSingleObject(listener_thread_, INFINITE);
		CloseHandle(listener_thread_);
		listener_thread_ = nullptr;
	}
	if (listener_)
	{
		freerdp_listener_free(listener_);
		listener_ = nullptr;
	}
	backend_->CancelAll(RdpdrError::Cancelled);
	if (fs_frontend_)
		fs_frontend_->StopMount();
	WLog_Print(WLog_Get(TAG), WLOG_INFO, "Listener stopped.");
}

void RdpServerCore::OnConnected()
{
	WLog_Print(WLog_Get(TAG), WLOG_INFO, "Client connected.");
	if (fs_frontend_)
		fs_frontend_->StartMount();
}

void RdpServerCore::OnDisconnected()
{
	WLog_Print(WLog_Get(TAG), WLOG_INFO, "Client disconnected.");
	backend_->CancelAll(RdpdrError::Cancelled);
	if (fs_frontend_)
		fs_frontend_->StopMount();
	session_active_ = false;
}

void RdpServerCore::NotifyDriveList(const std::vector<DriveInfo>& drives)
{
	backend_->UpdateDrives(drives);
	if (fs_frontend_)
		fs_frontend_->UpdateDriveList(drives);
}

BOOL RdpServerCore::PeerAccepted(freerdp_listener* instance, freerdp_peer* client)
{
	auto* server = static_cast<RdpServerCore*>(instance->info);
	if (!server || !client)
		return FALSE;
	if (server->session_active_.exchange(true))
	{
		WLog_Print(WLog_Get(TAG), WLOG_WARN, "Rejecting additional session (single-session mode)."
			);
		freerdp_peer_free(client);
		return FALSE;
	}
	client->ContextExtra = server;
	HANDLE hThread = CreateThread(NULL, 0, PeerMainLoop, client, 0, NULL);
	if (!hThread)
	{
		server->session_active_ = false;
		return FALSE;
	}
	CloseHandle(hThread);
	return TRUE;
}

DWORD WINAPI RdpServerCore::PeerMainLoop(LPVOID arg)
{
	freerdp_peer* client = static_cast<freerdp_peer*>(arg);
	if (!client)
		return 0;

	RdpServerCore* server = static_cast<RdpServerCore*>(client->ContextExtra);
	if (!server)
		return 0;

	if (!tsclient_peer_init(client))
	{
		freerdp_peer_free(client);
		server->session_active_ = false;
		return 0;
	}

	rdpSettings* settings = client->context->settings;
	if (!settings)
		goto fail;

	if (!freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, TRUE))
		goto fail;
	if (!freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, TRUE))
		goto fail;
	if (!freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, FALSE))
		goto fail;
	if (!freerdp_settings_set_uint32(settings, FreeRDP_EncryptionLevel,
	                                 ENCRYPTION_LEVEL_CLIENT_COMPATIBLE))
		goto fail;

	if (winpr_PathFileExists(server->config_.key_path.c_str()))
	{
		rdpPrivateKey* key = freerdp_key_new_from_file_enc(server->config_.key_path.c_str(), NULL);
		if (!key)
			goto fail;
		if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1))
			goto fail;
	}
	if (winpr_PathFileExists(server->config_.cert_path.c_str()))
	{
		rdpCertificate* cert = freerdp_certificate_new_from_file(server->config_.cert_path.c_str());
		if (!cert)
			goto fail;
		if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, cert, 1))
			goto fail;
	}

	client->PostConnect = tsclient_peer_post_connect;
	client->Activate = tsclient_peer_activate;

	if (!client->Initialize(client))
		goto fail;

	while (server->running_)
	{
		HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
		DWORD count = 0;
		DWORD status = 0;

		DWORD tmp = client->GetEventHandles(client, handles, 32);
		if (tmp == 0)
			break;
		count += tmp;

		auto* context = reinterpret_cast<TsclientPeerContext*>(client->context);
		if (context && context->vcm)
		{
			HANDLE channelHandle = WTSVirtualChannelManagerGetEventHandle(context->vcm);
			handles[count++] = channelHandle;
		}

		status = WaitForMultipleObjects(count, handles, FALSE, 250);
		if (status == WAIT_TIMEOUT)
		{
			if (!server->running_)
				break;
			continue;
		}
		if (status == WAIT_FAILED)
			break;

		if (client->CheckFileDescriptor(client) != TRUE)
			break;

		if (context && context->vcm)
			if (WTSVirtualChannelManagerCheckFileDescriptor(context->vcm) != TRUE)
				break;
	}

	client->Disconnect(client);
fail:
	if (client->context)
		server->OnDisconnected();
	freerdp_peer_context_free(client);
	freerdp_peer_free(client);
	return 0;
}

void RdpServerCore::ServerMainLoop(RdpServerCore* server)
{
	if (!server || !server->listener_)
		return;
	while (server->running_)
	{
		HANDLE handles[32] = { 0 };
		DWORD count = server->listener_->GetEventHandles(server->listener_, handles, 32);
		if (count == 0)
			break;
		DWORD status = WaitForMultipleObjects(count, handles, FALSE, 250);
		if (status == WAIT_TIMEOUT)
		{
			if (!server->running_)
				break;
			continue;
		}
		if (status == WAIT_FAILED)
			break;
		if (server->listener_->CheckFileDescriptor(server->listener_) != TRUE)
			break;
	}
}

} // namespace tsclient
