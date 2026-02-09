#include "vfs_frontend.h"

#include <cerrno>
#include <cstring>
#include <thread>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <freerdp/log.h>
#include <freerdp/channels/rdpdr.h>
#include <winpr/file.h>

#if defined(TSCLIENT_WITH_MACFUSE)
#include <fuse/fuse.h>
#endif

#define TAG SERVER_TAG("tsclient-vfs")

namespace tsclient
{

namespace
{
constexpr std::uint64_t kFileTimeToUnixEpoch = 116444736000000000ULL;

int MapError(RdpdrError error)
{
	switch (error)
	{
		case RdpdrError::Ok:
			return 0;
		case RdpdrError::NotFound:
			return -ENOENT;
		case RdpdrError::AccessDenied:
			return -EACCES;
		case RdpdrError::Busy:
			return -EBUSY;
		case RdpdrError::Timeout:
			return -ETIMEDOUT;
		case RdpdrError::NotConnected:
			return -ENOTCONN;
		default:
			return -EIO;
	}
}

time_t FileTimeToUnixSeconds(std::uint64_t filetime)
{
	if (filetime < kFileTimeToUnixEpoch)
		return 0;
	return static_cast<time_t>((filetime - kFileTimeToUnixEpoch) / 10000000ULL);
}

std::string ParentRemotePath(const std::string& remote_path)
{
	if (remote_path.empty() || remote_path == "\\")
		return "\\";
	const auto pos = remote_path.find_last_of('\\');
	if (pos == std::string::npos || pos == 0)
		return "\\";
	return remote_path.substr(0, pos);
}

bool PopulateStatFromInfo(const QueryInfoResult& basic, const QueryInfoResult& standard,
                          struct ::stat* stbuf)
{
	if (basic.payload.size() < 36)
		return false;

	std::uint64_t creation_time = 0;
	std::uint64_t last_access_time = 0;
	std::uint64_t last_write_time = 0;
	std::uint64_t change_time = 0;
	std::uint32_t file_attributes = 0;
	std::memcpy(&creation_time, basic.payload.data(), sizeof(creation_time));
	std::memcpy(&last_access_time, basic.payload.data() + 8, sizeof(last_access_time));
	std::memcpy(&last_write_time, basic.payload.data() + 16, sizeof(last_write_time));
	std::memcpy(&change_time, basic.payload.data() + 24, sizeof(change_time));
	std::memcpy(&file_attributes, basic.payload.data() + 32, sizeof(file_attributes));

	std::uint64_t end_of_file = 0;
	std::uint32_t number_of_links = 1;
	std::uint8_t directory_flag = 0;
	if (standard.payload.size() >= 22)
	{
		std::memcpy(&end_of_file, standard.payload.data() + 8, sizeof(end_of_file));
		std::memcpy(&number_of_links, standard.payload.data() + 16, sizeof(number_of_links));
		std::memcpy(&directory_flag, standard.payload.data() + 21, sizeof(directory_flag));
	}

	const bool is_directory =
	    (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || directory_flag != 0;
	stbuf->st_mode = is_directory ? (S_IFDIR | 0755) : (S_IFREG | 0644);
	stbuf->st_nlink = number_of_links > 0 ? number_of_links : (is_directory ? 2 : 1);
	stbuf->st_size = is_directory ? 0 : static_cast<off_t>(end_of_file);
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_blksize = 4096;
	stbuf->st_blocks = static_cast<blkcnt_t>((stbuf->st_size + 511) / 512);

	stbuf->st_atime = FileTimeToUnixSeconds(last_access_time);
	stbuf->st_mtime = FileTimeToUnixSeconds(last_write_time);
	stbuf->st_ctime = FileTimeToUnixSeconds(change_time);
#if defined(__APPLE__)
	stbuf->st_birthtime = FileTimeToUnixSeconds(creation_time);
#endif
	return true;
}

} // namespace

MacFuseFrontend::MacFuseFrontend(RdpdrBackend* backend, std::string mount_root)
    : backend_(backend),
      mapper_(mount_root),
      mount_root_(std::move(mount_root)),
      directory_cache_(std::chrono::milliseconds(250)),
      metadata_cache_(std::chrono::milliseconds(250)),
      op_timeout_(std::chrono::seconds(5)),
      next_handle_(1)
{
}

bool MacFuseFrontend::StartMount()
{
	if (mounted_)
		return true;
#if defined(TSCLIENT_WITH_MACFUSE)
	if (mkdir(mount_root_.c_str(), 0700) != 0 && errno != EEXIST)
	{
		WLog_Print(WLog_Get(TAG), WLOG_ERROR, "Failed to create mount root '%s': %s",
		           mount_root_.c_str(), strerror(errno));
		return false;
	}
	stop_requested_.store(false);
	mount_thread_ = std::thread([this]() {
		struct fuse_operations ops = {};
		ops.getattr = [](const char* path, struct ::stat* stbuf) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			return self->HandleGetAttr(self->ToAbsolutePath(path), stbuf);
		};
		ops.readdir = [](const char* path, void* buf, fuse_fill_dir_t filler, off_t,
		                 struct fuse_file_info*) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			return self->HandleReadDir(self->ToAbsolutePath(path), buf, filler);
		};
		ops.statfs = [](const char* path, struct statvfs* stbuf) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			return self->HandleStatFs(self->ToAbsolutePath(path), stbuf);
		};
		ops.open = [](const char* path, struct fuse_file_info* fi) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			const auto mapped = self->mapper_.MapPath(self->ToAbsolutePath(path));
			if (!mapped)
				return -ENOENT;
			const bool write = (fi->flags & O_ACCMODE) != O_RDONLY;
			const std::uint32_t access = write ? (FILE_GENERIC_READ | FILE_GENERIC_WRITE)
			                                   : FILE_GENERIC_READ;
			auto result = self->backend_->OpenFile(mapped->device_id, mapped->remote_path, access,
			                                     FILE_OPEN, self->op_timeout_);
			if (result.error != RdpdrError::Ok)
				return MapError(result.error);
			MacFuseFrontend::HandleState state;
			state.handle = result.handle;
			state.is_directory = false;
			state.path = mapped->remote_path;
			fi->fh = self->RegisterHandle(state);
			return 0;
		};
		ops.create = [](const char* path, mode_t, struct fuse_file_info* fi) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			const auto mapped = self->mapper_.MapPath(self->ToAbsolutePath(path));
			if (!mapped)
				return -ENOENT;
			auto result = self->backend_->OpenFile(mapped->device_id, mapped->remote_path,
			                                     FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_CREATE,
			                                     self->op_timeout_);
			if (result.error != RdpdrError::Ok)
				return MapError(result.error);
			MacFuseFrontend::HandleState state;
			state.handle = result.handle;
			state.is_directory = false;
			state.path = mapped->remote_path;
			fi->fh = self->RegisterHandle(state);
			return 0;
		};
		ops.read = [](const char* path, char* buf, size_t size, off_t offset,
		              struct fuse_file_info* fi) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			MacFuseFrontend::HandleState* state = self->LookupHandle(fi->fh);
			FileHandle handle;
			if (state)
				handle = state->handle;
			else
			{
				const auto mapped = self->mapper_.MapPath(self->ToAbsolutePath(path));
				if (!mapped)
					return -ENOENT;
				auto open = self->backend_->OpenFile(mapped->device_id, mapped->remote_path,
				                                   FILE_GENERIC_READ, FILE_OPEN,
				                                   self->op_timeout_);
				if (open.error != RdpdrError::Ok)
					return MapError(open.error);
				handle = open.handle;
			}
			auto result = self->backend_->ReadFile(handle, static_cast<std::uint64_t>(offset),
			                                     static_cast<std::uint32_t>(size),
			                                     self->op_timeout_);
			if (!state)
				self->backend_->CloseFile(handle, self->op_timeout_);
			if (result.error != RdpdrError::Ok)
				return MapError(result.error);
			std::memcpy(buf, result.data.data(), result.data.size());
			return static_cast<int>(result.data.size());
		};
		ops.write = [](const char* path, const char* buf, size_t size, off_t offset,
		               struct fuse_file_info* fi) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			MacFuseFrontend::HandleState* state = self->LookupHandle(fi->fh);
			FileHandle handle;
			if (state)
				handle = state->handle;
			else
			{
				const auto mapped = self->mapper_.MapPath(self->ToAbsolutePath(path));
				if (!mapped)
					return -ENOENT;
				auto open = self->backend_->OpenFile(mapped->device_id, mapped->remote_path,
				                                   FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OPEN,
				                                   self->op_timeout_);
				if (open.error != RdpdrError::Ok)
					return MapError(open.error);
				handle = open.handle;
			}
			std::vector<std::uint8_t> data(buf, buf + size);
			auto result = self->backend_->WriteFile(handle, static_cast<std::uint64_t>(offset), data,
			                                      self->op_timeout_);
			if (!state)
				self->backend_->CloseFile(handle, self->op_timeout_);
			if (result.error != RdpdrError::Ok)
				return MapError(result.error);
			return static_cast<int>(result.bytes_written);
		};
		ops.release = [](const char*, struct fuse_file_info* fi) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			auto* state = self->LookupHandle(fi->fh);
			if (state)
			{
				self->backend_->CloseFile(state->handle, self->op_timeout_);
				self->UnregisterHandle(fi->fh);
			}
			return 0;
		};
		ops.mkdir = [](const char* path, mode_t) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			const auto mapped = self->mapper_.MapPath(self->ToAbsolutePath(path));
			if (!mapped)
				return -ENOENT;
			auto result = self->backend_->CreateDirectory(mapped->device_id, mapped->remote_path,
			                                            self->op_timeout_);
			return MapError(result.error);
		};
		ops.rmdir = [](const char* path) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			const auto mapped = self->mapper_.MapPath(self->ToAbsolutePath(path));
			if (!mapped)
				return -ENOENT;
			auto result = self->backend_->DeleteDirectory(mapped->device_id, mapped->remote_path,
			                                            self->op_timeout_);
			return MapError(result.error);
		};
		ops.unlink = [](const char* path) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			const auto mapped = self->mapper_.MapPath(self->ToAbsolutePath(path));
			if (!mapped)
				return -ENOENT;
			auto result = self->backend_->DeleteFile(mapped->device_id, mapped->remote_path,
			                                       self->op_timeout_);
			return MapError(result.error);
		};
#if FUSE_USE_VERSION >= 30
		ops.rename = [](const char* from, const char* to, unsigned int) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			const auto from_mapped = self->mapper_.MapPath(self->ToAbsolutePath(from));
			const auto to_mapped = self->mapper_.MapPath(self->ToAbsolutePath(to));
			if (!from_mapped || !to_mapped)
				return -ENOENT;
			auto result = self->backend_->RenameFile(from_mapped->device_id, from_mapped->remote_path,
			                                       to_mapped->remote_path, self->op_timeout_);
			return MapError(result.error);
		};
#else
		ops.rename = [](const char* from, const char* to) -> int {
			auto* self = static_cast<MacFuseFrontend*>(fuse_get_context()->private_data);
			const auto from_mapped = self->mapper_.MapPath(self->ToAbsolutePath(from));
			const auto to_mapped = self->mapper_.MapPath(self->ToAbsolutePath(to));
			if (!from_mapped || !to_mapped)
				return -ENOENT;
			auto result = self->backend_->RenameFile(from_mapped->device_id, from_mapped->remote_path,
			                                       to_mapped->remote_path, self->op_timeout_);
			return MapError(result.error);
		};
#endif

		char* argv[] = { const_cast<char*>("tsclientd"), const_cast<char*>("-f"),
		                const_cast<char*>(mount_root_.c_str()) };
		int argc = 3;
		struct fuse_args fargs = FUSE_ARGS_INIT(argc, argv);
		fuse_chan_ = fuse_mount(mount_root_.c_str(), &fargs);
		if (!fuse_chan_)
		{
			WLog_Print(WLog_Get(TAG), WLOG_ERROR, "fuse_mount failed.");
			return;
		}
		fuse_ = fuse_new(fuse_chan_, &fargs, &ops, sizeof(ops), this);
		if (!fuse_)
		{
			WLog_Print(WLog_Get(TAG), WLOG_ERROR, "fuse_new failed.");
			fuse_unmount(mount_root_.c_str(), fuse_chan_);
			fuse_chan_ = nullptr;
			return;
		}
		mounted_ = true;
		fuse_loop_mt(fuse_);
		fuse_unmount(mount_root_.c_str(), fuse_chan_);
		fuse_chan_ = nullptr;
		fuse_destroy(fuse_);
		fuse_ = nullptr;
		mounted_ = false;
	});
	return true;
#else
	WLog_Print(WLog_Get(TAG), WLOG_WARN,
	           "macFUSE support not compiled. Rebuild with -DWITH_MACFUSE=ON.");
	return false;
#endif
}

void MacFuseFrontend::StopMount()
{
#if defined(TSCLIENT_WITH_MACFUSE)
	if (!mounted_)
		return;
	stop_requested_.store(true);
	if (fuse_)
		fuse_exit(fuse_);
	if (mount_thread_.joinable())
		mount_thread_.join();
	mounted_ = false;
#else
	mounted_ = false;
#endif
}

void MacFuseFrontend::UpdateDriveList(const std::vector<DriveInfo>& drives)
{
	mapper_.UpdateDrives(drives);
	directory_cache_.Clear();
	metadata_cache_.Clear();
}

RdpdrResult MacFuseFrontend::ListDirectory(const std::string& absolute_path)
{
	if (mapper_.IsRoot(absolute_path))
		return { RdpdrError::Ok, {} };

	if (auto cached = directory_cache_.Get(absolute_path))	
		return { cached->error, {} };
	const auto mapped = mapper_.MapPath(absolute_path);
	if (!mapped)
		return { RdpdrError::NotFound, {} };

	auto result = backend_->QueryDirectory(mapped->device_id, mapped->remote_path, op_timeout_);
	if (result.error == RdpdrError::Ok)
		directory_cache_.Put(absolute_path, result);
	return { result.error, {} };
}

RdpdrResult MacFuseFrontend::ReadFile(const std::string& absolute_path, std::uint64_t offset,
                                      std::uint32_t length)
{
	const auto mapped = mapper_.MapPath(absolute_path);
	if (!mapped)
		return { RdpdrError::NotFound, {} };

	auto open = backend_->OpenFile(mapped->device_id, mapped->remote_path, FILE_GENERIC_READ,
	                             FILE_OPEN, op_timeout_);
	if (open.error != RdpdrError::Ok)
		return { open.error, {} };
	auto result = backend_->ReadFile(open.handle, offset, length, op_timeout_);
	backend_->CloseFile(open.handle, op_timeout_);
	return { result.error, std::move(result.data) };
}

RdpdrResult MacFuseFrontend::WriteFile(const std::string& absolute_path, std::uint64_t offset,
                                       const std::vector<std::uint8_t>& data)
{
	const auto mapped = mapper_.MapPath(absolute_path);
	if (!mapped)
		return { RdpdrError::NotFound, {} };

	auto open = backend_->OpenFile(mapped->device_id, mapped->remote_path,
	                             FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OPEN, op_timeout_);
	if (open.error != RdpdrError::Ok)
		return { open.error, {} };
	auto result = backend_->WriteFile(open.handle, offset, data, op_timeout_);
	backend_->CloseFile(open.handle, op_timeout_);
	return { result.error, {} };
}

MacFuseFrontend::HandleState* MacFuseFrontend::LookupHandle(std::uint64_t fh)
{
	std::lock_guard<std::mutex> lock(handles_mutex_);
	auto it = handles_.find(fh);
	if (it == handles_.end())
		return nullptr;
	return &it->second;
}

std::uint64_t MacFuseFrontend::RegisterHandle(const HandleState& state)
{
	std::lock_guard<std::mutex> lock(handles_mutex_);
	const std::uint64_t handle = next_handle_++;
	handles_.emplace(handle, state);
	return handle;
}

void MacFuseFrontend::UnregisterHandle(std::uint64_t fh)
{
	std::lock_guard<std::mutex> lock(handles_mutex_);
	handles_.erase(fh);
}

std::string MacFuseFrontend::ToAbsolutePath(const std::string& fuse_path) const
{
		if (fuse_path == "/" || fuse_path.empty())
			return mount_root_;
	if (mount_root_.back() == '/')
		return mount_root_ + fuse_path.substr(1);
	return mount_root_ + fuse_path;
}

int MacFuseFrontend::HandleGetAttr(const std::string& absolute_path, struct ::stat* stbuf)
{
	std::memset(stbuf, 0, sizeof(struct stat));
	if (mapper_.IsRoot(absolute_path))
	{
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}

	const auto mapped = mapper_.MapPath(absolute_path);
	if (!mapped)
		return -ENOENT;

	if (mapped->remote_path == "\\")
	{
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}

	if (auto cached = metadata_cache_.Get(absolute_path))
	{
		if (PopulateStatFromInfo(cached->basic, cached->standard, stbuf))
			return 0;
		metadata_cache_.Erase(absolute_path);
	}

	auto open = backend_->OpenFile(mapped->device_id, mapped->remote_path, FILE_READ_ATTRIBUTES,
	                               FILE_OPEN, op_timeout_);
	if (open.error != RdpdrError::Ok)
		return MapError(open.error);

	auto info = backend_->QueryInformation(open.handle, FileBasicInformation, op_timeout_);
	auto standard = backend_->QueryInformation(open.handle, FileStandardInformation, op_timeout_);
	backend_->CloseFile(open.handle, op_timeout_);

	if (info.error != RdpdrError::Ok)
		return MapError(info.error);

	if (standard.error != RdpdrError::Ok)
		standard.payload.clear();

	metadata_cache_.Put(absolute_path, FileInfoCache{ info, standard });
	if (PopulateStatFromInfo(info, standard, stbuf))
		return 0;

	return -ENOENT;
}

int MacFuseFrontend::HandleReadDir(const std::string& absolute_path, void* buf,
                                   int (*filler)(void*, const char*, const struct ::stat*, off_t))
{
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	if (mapper_.IsRoot(absolute_path))
	{
		for (const auto& drive : mapper_.Drives())
			filler(buf, drive.dos_name.c_str(), NULL, 0);
		return 0;
	}
	const auto mapped = mapper_.MapPath(absolute_path);
	if (!mapped)
		return -ENOENT;

	auto cached = directory_cache_.Get(absolute_path);
	QueryDirectoryResult result;
	if (cached)
		result = *cached;
	else
	{
		result = backend_->QueryDirectory(mapped->device_id, mapped->remote_path, op_timeout_);
		if (result.error == RdpdrError::Ok)
			directory_cache_.Put(absolute_path, result);
	}
	if (result.error != RdpdrError::Ok)
		return MapError(result.error);

	for (const auto& entry : result.entries)
	{
		filler(buf, entry.name.c_str(), NULL, 0);
	}
	return 0;
}

int MacFuseFrontend::HandleStatFs(const std::string& absolute_path, struct statvfs* stbuf)
{
	std::memset(stbuf, 0, sizeof(struct statvfs));
	stbuf->f_namemax = 255;
	if (mapper_.IsRoot(absolute_path))
	{
		stbuf->f_bsize = 4096;
		stbuf->f_frsize = 4096;
		return 0;
	}

	const auto mapped = mapper_.MapPath(absolute_path);
	if (!mapped)
		return -ENOENT;

	auto info =
	    backend_->QueryVolumeInformation(mapped->device_id, FileFsFullSizeInformation, op_timeout_);
	if (info.error != RdpdrError::Ok)
		return MapError(info.error);

	if (info.payload.size() < 32)
		return -EIO;

	std::uint64_t total_units = 0;
	std::uint64_t caller_available_units = 0;
	std::uint64_t actual_available_units = 0;
	std::uint32_t sectors_per_allocation_unit = 0;
	std::uint32_t bytes_per_sector = 0;
	std::memcpy(&total_units, info.payload.data(), sizeof(total_units));
	std::memcpy(&caller_available_units, info.payload.data() + 8, sizeof(caller_available_units));
	std::memcpy(&actual_available_units, info.payload.data() + 16,
	            sizeof(actual_available_units));
	std::memcpy(&sectors_per_allocation_unit, info.payload.data() + 24,
	            sizeof(sectors_per_allocation_unit));
	std::memcpy(&bytes_per_sector, info.payload.data() + 28, sizeof(bytes_per_sector));

	const std::uint64_t allocation_bytes =
	    static_cast<std::uint64_t>(sectors_per_allocation_unit) *
	    static_cast<std::uint64_t>(bytes_per_sector);
	stbuf->f_bsize = allocation_bytes > 0 ? allocation_bytes : 4096;
	stbuf->f_frsize = stbuf->f_bsize;
	stbuf->f_blocks = static_cast<fsblkcnt_t>(total_units);
	stbuf->f_bfree = static_cast<fsblkcnt_t>(actual_available_units);
	stbuf->f_bavail = static_cast<fsblkcnt_t>(caller_available_units);
	return 0;
}

} // namespace tsclient
