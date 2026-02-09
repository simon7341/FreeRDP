#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <sys/stat.h>
#include <sys/statvfs.h>

#if defined(TSCLIENT_WITH_MACFUSE)
struct fuse;
struct fuse_chan;
#endif

#include "path_mapper.h"
#include "rdpdr_backend.h"
#include "rdpdr_transport.h"
#include "ttl_cache.h"

namespace tsclient
{

class MacFuseFrontend : public IFileSystemFrontend
{
  public:
	MacFuseFrontend(RdpdrBackend* backend, std::string mount_root);

	bool StartMount() override;
	void StopMount() override;
	void UpdateDriveList(const std::vector<DriveInfo>& drives) override;

	// Minimal VFS surface to support basic operations without macFUSE bindings.
	RdpdrResult ListDirectory(const std::string& absolute_path);
	RdpdrResult ReadFile(const std::string& absolute_path, std::uint64_t offset,
	                     std::uint32_t length);
	RdpdrResult WriteFile(const std::string& absolute_path, std::uint64_t offset,
	                      const std::vector<std::uint8_t>& data);

  private:
	struct FileInfoCache
	{
		QueryInfoResult basic;
		QueryInfoResult standard;
	};

	struct HandleState
	{
		FileHandle handle;
		bool is_directory = false;
		std::string path;
	};

	HandleState* LookupHandle(std::uint64_t fh);
	std::uint64_t RegisterHandle(const HandleState& state);
	void UnregisterHandle(std::uint64_t fh);
	std::string ToAbsolutePath(const std::string& fuse_path) const;

	int HandleGetAttr(const std::string& absolute_path, struct ::stat* stbuf);
	int HandleReadDir(const std::string& absolute_path, void* buf,
	                  int (*filler)(void*, const char*, const struct ::stat*, off_t));
	int HandleStatFs(const std::string& absolute_path, struct statvfs* stbuf);

	RdpdrBackend* backend_ = nullptr;
	PathMapper mapper_;
	std::string mount_root_;
	TtlCache<QueryDirectoryResult> directory_cache_;
	TtlCache<FileInfoCache> metadata_cache_;
	std::chrono::milliseconds op_timeout_;
	bool mounted_ = false;

	std::mutex handles_mutex_;
	std::unordered_map<std::uint64_t, HandleState> handles_;
	std::atomic<std::uint64_t> next_handle_;

	std::thread mount_thread_;
	std::atomic<bool> stop_requested_{ false };
#if defined(TSCLIENT_WITH_MACFUSE)
	struct ::fuse* fuse_ = nullptr;
	struct ::fuse_chan* fuse_chan_ = nullptr;
#endif
};

} // namespace tsclient
