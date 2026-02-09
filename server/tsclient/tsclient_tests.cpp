#include <cassert>
#include <chrono>
#include <thread>

#include <winpr/file.h>

#include "path_mapper.h"
#include "ttl_cache.h"
#include "rdpdr_backend.h"

using namespace tsclient;

static UINT FakeDriveOpenFile(RdpdrServerContext* context, void* callbackData, UINT32 deviceId,
                              const char* path, UINT32 desiredAccess, UINT32 createDisposition)
{
	(void)context;
	(void)callbackData;
	(void)deviceId;
	(void)path;
	(void)desiredAccess;
	(void)createDisposition;
	return CHANNEL_RC_OK;
}

int main()
{
	// PathMapper tests
	{
		PathMapper mapper("/Volumes/tsclient");
		mapper.UpdateDrives({ { 1, "C" }, { 2, "D" } });
		auto mapped = mapper.MapPath("/Volumes/tsclient/C/Users/test.txt");
		assert(mapped.has_value());
		assert(mapped->device_id == 1);
		assert(mapped->remote_path == "\\Users\\test.txt");
		assert(mapper.IsRoot("/Volumes/tsclient"));
		assert(!mapper.MapPath("/Volumes/other/C"));
	}

	// TtlCache tests
	{
		TtlCache<int> cache(std::chrono::milliseconds(20));
		cache.Put("foo", 42);
		auto value = cache.Get("foo");
		assert(value.has_value() && *value == 42);
		std::this_thread::sleep_for(std::chrono::milliseconds(30));
		auto expired = cache.Get("foo");
		assert(!expired.has_value());
	}

	// Pending request timeout test
	{
		RdpdrBackend backend(nullptr);
		RdpdrServerContext context = {};
		context.DriveOpenFile = FakeDriveOpenFile;
		backend.AttachServerContext(&context);
		auto result = backend.OpenFile(1, "\\foo.txt", FILE_GENERIC_READ, FILE_OPEN,
		                               std::chrono::milliseconds(10));
		assert(result.error == RdpdrError::Timeout);
		backend.DetachServerContext();
	}

	return 0;
}
