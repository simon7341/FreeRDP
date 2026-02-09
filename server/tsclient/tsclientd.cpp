#include <atomic>
#include <csignal>
#include <thread>
#include <pthread.h>

#include <freerdp/log.h>
#include <freerdp/channels/channels.h>
#include <freerdp/channels/wtsvc.h>
#include <winpr/ssl.h>

#include "rdp_server_core.h"
#include "rdpdr_backend.h"
#include "vfs_frontend.h"

#define TAG SERVER_TAG("tsclient-main")

static std::atomic<bool> g_running{ true };

int main(int argc, char** argv)
{
	using namespace tsclient;
	WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi());
	winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);

	ServerConfig config;
	std::string mount_root = "/Volumes/tsclient";

	for (int i = 1; i < argc; ++i)
	{
		const std::string arg = argv[i];
		if (arg == "--bind" && i + 1 < argc)
			config.bind_address = argv[++i];
		else if (arg == "--port" && i + 1 < argc)
			config.port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
		else if (arg == "--mount-root" && i + 1 < argc)
			mount_root = argv[++i];
		else if (arg == "--cert" && i + 1 < argc)
			config.cert_path = argv[++i];
		else if (arg == "--key" && i + 1 < argc)
			config.key_path = argv[++i];
		else if (arg == "--local-only")
			config.local_only = true;
	}

	// Block signals in all threads; handle them in a dedicated sigwait thread.
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

	RdpdrBackend backend(nullptr);
	MacFuseFrontend vfs(&backend, mount_root);
	RdpServerCore server(&backend);

	if (!server.Start(config, &vfs))
	{
		WLog_Print(WLog_Get(TAG), WLOG_ERROR, "Failed to start tsclient server.");
		return 1;
	}

	std::thread signal_thread([&]() {
		int sig = 0;
		if (sigwait(&sigset, &sig) == 0)
		{
			WLog_Print(WLog_Get(TAG), WLOG_INFO, "Signal %d received, shutting down.", sig);
			g_running = false;
		}
	});

	WLog_Print(WLog_Get(TAG), WLOG_INFO, "tsclientd running. Press Ctrl+C to stop.");
	while (g_running.load())
		std::this_thread::sleep_for(std::chrono::milliseconds(100));

	server.Stop();
	if (signal_thread.joinable())
		signal_thread.join();
	return 0;
}
