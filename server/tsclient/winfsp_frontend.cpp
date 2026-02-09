#include "winfsp_frontend.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <vector>

#include <freerdp/log.h>

#include "rdpdr_backend.h"

#if defined(_WIN32) && defined(TSCLIENT_WITH_WINFSP)
#include <windows.h>
#include <winpr/nt.h>
#include <winpr/file.h>
#include <winfsp/winfsp.h>
#endif

namespace tsclient
{

#define TAG SERVER_TAG("tsclient-winfsp")

WinFspFrontend::WinFspFrontend(RdpdrBackend* backend, std::string mount_point)
    : backend_(backend), mount_point_(std::move(mount_point))
{
}

#if defined(_WIN32) && defined(TSCLIENT_WITH_WINFSP)

namespace
{
struct FileContext
{
	FileHandle handle{};
	bool has_handle = false;
	bool is_directory = false;
	std::string remote_path;
	std::uint32_t device_id = 0;
};

NTSTATUS MapStatus(RdpdrError error)
{
	switch (error)
	{
		case RdpdrError::Ok:
			return STATUS_SUCCESS;
		case RdpdrError::NotFound:
			return STATUS_OBJECT_NAME_NOT_FOUND;
		case RdpdrError::AccessDenied:
			return STATUS_ACCESS_DENIED;
		case RdpdrError::Busy:
			return STATUS_SHARING_VIOLATION;
		case RdpdrError::Timeout:
			return STATUS_IO_TIMEOUT;
		case RdpdrError::NotConnected:
			return STATUS_DEVICE_NOT_CONNECTED;
		case RdpdrError::NotSupported:
			return STATUS_NOT_SUPPORTED;
		case RdpdrError::InvalidDevice:
			return STATUS_INVALID_DEVICE_REQUEST;
		default:
			return STATUS_IO_DEVICE_ERROR;
	}
}

std::wstring Utf8ToWide(const std::string& value)
{
	if (value.empty())
		return {};
	const int size =
	    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
	if (size <= 0)
		return {};
	std::wstring out(static_cast<size_t>(size - 1), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, out.data(), size);
	return out;
}

bool IsDriveLetterMount(const std::wstring& mount_point)
{
	if (mount_point.size() == 2 && mount_point[1] == L':')
		return true;
	if (mount_point.size() == 3 && mount_point[1] == L':' &&
	    (mount_point[2] == L'\\' || mount_point[2] == L'/'))
		return true;
	return false;
}

std::wstring NormalizeMountPoint(const std::wstring& mount_point)
{
	if (mount_point.empty())
		return mount_point;
	if (mount_point.size() == 1 &&
	    ((mount_point[0] >= L'A' && mount_point[0] <= L'Z') ||
	     (mount_point[0] >= L'a' && mount_point[0] <= L'z')))
	{
		std::wstring normalized;
		normalized.push_back(static_cast<wchar_t>(towupper(mount_point[0])));
		normalized.push_back(L':');
		return normalized;
	}
	if (IsDriveLetterMount(mount_point))
	{
		std::wstring normalized = mount_point;
		normalized[0] = static_cast<wchar_t>(towupper(normalized[0]));
		if (normalized.size() == 3)
			normalized.resize(2);
		return normalized;
	}
	return mount_point;
}

bool EnsureDirectoryMount(const std::wstring& mount_point)
{
	if (mount_point.empty())
		return false;
	DWORD attrs = GetFileAttributesW(mount_point.c_str());
	if (attrs != INVALID_FILE_ATTRIBUTES)
		return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
	if (!CreateDirectoryW(mount_point.c_str(), nullptr))
		return false;
	return true;
}

std::string WideToUtf8(const wchar_t* value)
{
	if (!value || *value == L'\0')
		return {};
	const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
	if (size <= 0)
		return {};
	std::string out(static_cast<size_t>(size - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), size, nullptr, nullptr);
	return out;
}

struct MappedPath
{
	bool is_root = false;
	std::uint32_t device_id = 0;
	std::string remote_path;
};

std::string ToRemotePath(const std::wstring& suffix)
{
	if (suffix.empty())
		return "\\";
	std::string utf8 = WideToUtf8(suffix.c_str());
	std::replace(utf8.begin(), utf8.end(), '/', '\\');
	if (!utf8.empty() && utf8.front() != '\\')
		utf8.insert(utf8.begin(), '\\');
	return utf8;
}

bool LookupDrive(const std::vector<DriveInfo>& drives, const std::wstring& drive_name,
                 std::uint32_t* device_id)
{
	if (!device_id)
		return false;
	for (const auto& drive : drives)
	{
		auto drive_w = Utf8ToWide(drive.dos_name);
		if (_wcsicmp(drive_w.c_str(), drive_name.c_str()) == 0)
		{
			*device_id = drive.device_id;
			return true;
		}
	}
	return false;
}

MappedPath MapFileName(const std::vector<DriveInfo>& drives, PWSTR file_name)
{
	MappedPath mapped;
	if (!file_name || file_name[0] == L'\0' || wcscmp(file_name, L"\\") == 0)
	{
		mapped.is_root = true;
		return mapped;
	}

	std::wstring full(file_name);
	if (!full.empty() && full.front() == L'\\')
		full.erase(full.begin());

	const auto pos = full.find(L'\\');
	std::wstring drive = pos == std::wstring::npos ? full : full.substr(0, pos);
	std::wstring suffix = pos == std::wstring::npos ? L"" : full.substr(pos);

	if (!LookupDrive(drives, drive, &mapped.device_id))
		return mapped;

	mapped.remote_path = ToRemotePath(suffix);
	return mapped;
}

bool PopulateFileInfo(const QueryInfoResult& basic, const QueryInfoResult& standard,
                      FSP_FSCTL_FILE_INFO* file_info)
{
	if (!file_info || basic.payload.size() < 36)
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

	std::uint64_t allocation_size = 0;
	std::uint64_t end_of_file = 0;
	std::uint32_t number_of_links = 1;
	std::uint8_t directory_flag = 0;
	if (standard.payload.size() >= 22)
	{
		std::memcpy(&allocation_size, standard.payload.data(), sizeof(allocation_size));
		std::memcpy(&end_of_file, standard.payload.data() + 8, sizeof(end_of_file));
		std::memcpy(&number_of_links, standard.payload.data() + 16, sizeof(number_of_links));
		std::memcpy(&directory_flag, standard.payload.data() + 21, sizeof(directory_flag));
	}

	if (file_attributes == 0)
		file_attributes = FILE_ATTRIBUTE_NORMAL;
	if (directory_flag)
		file_attributes |= FILE_ATTRIBUTE_DIRECTORY;

	file_info->FileAttributes = file_attributes;
	file_info->ReparseTag = 0;
	file_info->FileSize = end_of_file;
	file_info->AllocationSize = allocation_size ? allocation_size : end_of_file;
	file_info->CreationTime = creation_time;
	file_info->LastAccessTime = last_access_time;
	file_info->LastWriteTime = last_write_time;
	file_info->ChangeTime = change_time;
	file_info->IndexNumber = 0;
	file_info->HardLinks = number_of_links > 0 ? number_of_links : 1;
	return true;
}

std::uint32_t MapDesiredAccess(ULONG granted_access)
{
	if (granted_access &
	    (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | DELETE))
		return FILE_GENERIC_READ | FILE_GENERIC_WRITE;
	return FILE_GENERIC_READ;
}

RdpdrError QueryInfoForPath(RdpdrBackend* backend, std::uint32_t device_id,
                            const std::string& remote_path, QueryInfoResult* basic,
                            QueryInfoResult* standard)
{
	if (!backend || !basic || !standard)
		return RdpdrError::NotConnected;
	auto open = backend->OpenFile(device_id, remote_path, FILE_READ_ATTRIBUTES, FILE_OPEN,
	                              std::chrono::milliseconds(5000));
	if (open.error != RdpdrError::Ok)
		return open.error;
	*basic = backend->QueryInformation(open.handle, FileBasicInformation,
	                                   std::chrono::milliseconds(5000));
	*standard = backend->QueryInformation(open.handle, FileStandardInformation,
	                                      std::chrono::milliseconds(5000));
	backend->CloseFile(open.handle, std::chrono::milliseconds(5000));
	if (basic->error != RdpdrError::Ok)
		return basic->error;
	if (standard->error != RdpdrError::Ok)
		standard->payload.clear();
	return RdpdrError::Ok;
}

NTSTATUS FillFileInfoForMapping(RdpdrBackend* backend, const MappedPath& mapped,
                                FSP_FSCTL_FILE_INFO* file_info)
{
	QueryInfoResult basic;
	QueryInfoResult standard;
	const auto error = QueryInfoForPath(backend, mapped.device_id, mapped.remote_path, &basic,
	                                    &standard);
	if (error != RdpdrError::Ok)
		return MapStatus(error);
	if (!PopulateFileInfo(basic, standard, file_info))
		return STATUS_IO_DEVICE_ERROR;
	return STATUS_SUCCESS;
}

NTSTATUS FillVolumeInfo(RdpdrBackend* backend, std::uint32_t device_id,
                        FSP_FSCTL_VOLUME_INFO* volume_info)
{
	if (!volume_info || !backend)
		return STATUS_INVALID_PARAMETER;
	auto info = backend->QueryVolumeInformation(device_id, FileFsFullSizeInformation,
	                                            std::chrono::milliseconds(5000));
	if (info.error != RdpdrError::Ok)
		return MapStatus(info.error);
	if (info.payload.size() < 32)
		return STATUS_IO_DEVICE_ERROR;

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

	const std::uint64_t alloc_bytes =
	    static_cast<std::uint64_t>(sectors_per_allocation_unit) *
	    static_cast<std::uint64_t>(bytes_per_sector);

	volume_info->TotalSize = total_units * alloc_bytes;
	volume_info->FreeSize = caller_available_units * alloc_bytes;
	return STATUS_SUCCESS;
}

NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM* file_system, FSP_FSCTL_VOLUME_INFO* volume_info)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	if (!self || !self->backend_)
		return STATUS_DEVICE_NOT_CONNECTED;
	std::vector<DriveInfo> drives;
	{
		std::lock_guard<std::mutex> lock(self->drives_mutex_);
		drives = self->drives_;
	}
	if (drives.empty())
	{
		volume_info->TotalSize = 0;
		volume_info->FreeSize = 0;
		return STATUS_SUCCESS;
	}
	return FillVolumeInfo(self->backend_, drives.front().device_id, volume_info);
}

NTSTATUS SetVolumeLabel(FSP_FILE_SYSTEM*, PWSTR, ULONG)
{
	return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS GetSecurityByName(FSP_FILE_SYSTEM* file_system, PWSTR file_name,
                           PUINT32 file_attributes, PSECURITY_DESCRIPTOR security_descriptor,
                           PSIZE_T security_descriptor_size)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	if (!self || !self->backend_)
		return STATUS_DEVICE_NOT_CONNECTED;

	std::vector<DriveInfo> drives;
	{
		std::lock_guard<std::mutex> lock(self->drives_mutex_);
		drives = self->drives_;
	}
	auto mapped = MapFileName(drives, file_name);
	if (mapped.is_root)
	{
		if (file_attributes)
			*file_attributes = FILE_ATTRIBUTE_DIRECTORY;
		if (security_descriptor_size)
			*security_descriptor_size = 0;
		return STATUS_SUCCESS;
	}
	if (mapped.device_id == 0)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	QueryInfoResult basic;
	QueryInfoResult standard;
	const auto error = QueryInfoForPath(self->backend_, mapped.device_id, mapped.remote_path,
	                                    &basic, &standard);
	if (error != RdpdrError::Ok)
		return MapStatus(error);

	if (basic.payload.size() >= 36 && file_attributes)
	{
		std::uint32_t attrs = 0;
		std::memcpy(&attrs, basic.payload.data() + 32, sizeof(attrs));
		*file_attributes = attrs ? attrs : FILE_ATTRIBUTE_NORMAL;
	}

	if (security_descriptor_size)
		*security_descriptor_size = 0;
	(void)security_descriptor;
	return STATUS_SUCCESS;
}

NTSTATUS Create(FSP_FILE_SYSTEM* file_system, PWSTR file_name, ULONG create_options,
                ULONG granted_access, ULONG, ULONG, PVOID* file_context,
                FSP_FSCTL_FILE_INFO* file_info)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	if (!self || !self->backend_)
		return STATUS_DEVICE_NOT_CONNECTED;

	std::vector<DriveInfo> drives;
	{
		std::lock_guard<std::mutex> lock(self->drives_mutex_);
		drives = self->drives_;
	}
	auto mapped = MapFileName(drives, file_name);
	if (mapped.is_root)
		return STATUS_ACCESS_DENIED;
	if (mapped.device_id == 0)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	const bool is_directory = (create_options & FILE_DIRECTORY_FILE) != 0;
	if (is_directory)
	{
		auto result = self->backend_->CreateDirectory(mapped.device_id, mapped.remote_path,
		                                             std::chrono::milliseconds(5000));
		if (result.error != RdpdrError::Ok)
			return MapStatus(result.error);
	}

	auto context = std::make_unique<FileContext>();
	context->device_id = mapped.device_id;
	context->remote_path = mapped.remote_path;
	context->is_directory = is_directory;

	if (!is_directory)
	{
		auto open = self->backend_->OpenFile(mapped.device_id, mapped.remote_path,
		                                    MapDesiredAccess(granted_access), FILE_CREATE,
		                                    std::chrono::milliseconds(5000));
		if (open.error != RdpdrError::Ok)
			return MapStatus(open.error);
		context->handle = open.handle;
		context->has_handle = true;
	}

	NTSTATUS status = FillFileInfoForMapping(self->backend_, mapped, file_info);
	if (status != STATUS_SUCCESS)
		return status;

	*file_context = context.release();
	return STATUS_SUCCESS;
}

NTSTATUS Open(FSP_FILE_SYSTEM* file_system, PWSTR file_name, ULONG granted_access,
              PVOID* file_context, FSP_FSCTL_FILE_INFO* file_info)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	if (!self || !self->backend_)
		return STATUS_DEVICE_NOT_CONNECTED;

	std::vector<DriveInfo> drives;
	{
		std::lock_guard<std::mutex> lock(self->drives_mutex_);
		drives = self->drives_;
	}
	auto mapped = MapFileName(drives, file_name);
	if (mapped.is_root)
	{
		auto context = std::make_unique<FileContext>();
		context->is_directory = true;
		context->remote_path = "\\";
		*file_context = context.release();
		std::memset(file_info, 0, sizeof(*file_info));
		file_info->FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
		return STATUS_SUCCESS;
	}
	if (mapped.device_id == 0)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	auto context = std::make_unique<FileContext>();
	context->device_id = mapped.device_id;
	context->remote_path = mapped.remote_path;

	auto open = self->backend_->OpenFile(mapped.device_id, mapped.remote_path,
	                                    MapDesiredAccess(granted_access), FILE_OPEN,
	                                    std::chrono::milliseconds(5000));
	if (open.error != RdpdrError::Ok)
		return MapStatus(open.error);
	context->handle = open.handle;
	context->has_handle = true;

	NTSTATUS status = FillFileInfoForMapping(self->backend_, mapped, file_info);
	if (status != STATUS_SUCCESS)
	{
		self->backend_->CloseFile(open.handle, std::chrono::milliseconds(5000));
		return status;
	}

	context->is_directory = (file_info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
	*file_context = context.release();
	return STATUS_SUCCESS;
}

NTSTATUS Overwrite(FSP_FILE_SYSTEM* file_system, PVOID file_context, ULONG file_attributes,
                   BOOLEAN, FSP_FSCTL_FILE_INFO* file_info)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (!self || !self->backend_ || !context)
		return STATUS_DEVICE_NOT_CONNECTED;
	if (context->is_directory)
		return STATUS_FILE_IS_A_DIRECTORY;

	std::uint64_t zero = 0;
	std::vector<std::uint8_t> payload(sizeof(zero));
	std::memcpy(payload.data(), &zero, sizeof(zero));
	FileHandle handle = context->handle;
	bool close_after = false;
	if (!context->has_handle)
	{
		auto open =
		    self->backend_->OpenFile(context->device_id, context->remote_path, FILE_WRITE_DATA,
		                             FILE_OPEN, std::chrono::milliseconds(5000));
		if (open.error != RdpdrError::Ok)
			return MapStatus(open.error);
		handle = open.handle;
		close_after = true;
	}

	auto result = self->backend_->SetInformation(handle, FileEndOfFileInformation,
	                                            payload, std::chrono::milliseconds(5000));
	if (close_after)
		self->backend_->CloseFile(handle, std::chrono::milliseconds(5000));
	if (result.error != RdpdrError::Ok)
		return MapStatus(result.error);

	if (file_attributes != 0)
	{
		std::vector<std::uint8_t> basic(36, 0);
		std::memcpy(basic.data() + 32, &file_attributes, sizeof(file_attributes));
		self->backend_->SetInformation(context->handle, FileBasicInformation, basic,
		                              std::chrono::milliseconds(5000));
	}

	if (file_info)
	{
		MappedPath mapped{ false, context->device_id, context->remote_path };
		FillFileInfoForMapping(self->backend_, mapped, file_info);
	}
	return STATUS_SUCCESS;
}

VOID Cleanup(FSP_FILE_SYSTEM* file_system, PVOID file_context, PWSTR file_name, ULONG flags)
{
	WINPR_UNUSED(file_name);
	if (!file_context)
		return;
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (!self || !self->backend_)
		return;
	if (flags & FspCleanupDelete)
	{
		if (context->is_directory)
			self->backend_->DeleteDirectory(context->device_id, context->remote_path,
			                               std::chrono::milliseconds(5000));
		else
			self->backend_->DeleteFile(context->device_id, context->remote_path,
			                          std::chrono::milliseconds(5000));
	}
}

VOID Close(FSP_FILE_SYSTEM* file_system, PVOID file_context)
{
	if (!file_context)
		return;
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (self && self->backend_ && context->has_handle)
		self->backend_->CloseFile(context->handle, std::chrono::milliseconds(5000));
	delete context;
}

NTSTATUS Read(FSP_FILE_SYSTEM* file_system, PVOID file_context, PVOID buffer, UINT64 offset,
              ULONG length, PULONG bytes_transferred)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (!self || !self->backend_ || !context)
		return STATUS_DEVICE_NOT_CONNECTED;
	if (context->is_directory)
		return STATUS_FILE_IS_A_DIRECTORY;
	if (bytes_transferred)
		*bytes_transferred = 0;

	auto result = self->backend_->ReadFile(context->handle, offset, length,
	                                      std::chrono::milliseconds(5000));
	if (result.error != RdpdrError::Ok)
		return MapStatus(result.error);
	if (buffer && !result.data.empty())
		std::memcpy(buffer, result.data.data(), result.data.size());
	if (bytes_transferred)
		*bytes_transferred = static_cast<ULONG>(result.data.size());
	return STATUS_SUCCESS;
}

NTSTATUS Write(FSP_FILE_SYSTEM* file_system, PVOID file_context, PVOID buffer, UINT64 offset,
               ULONG length, BOOLEAN write_to_end_of_file, BOOLEAN constrained_io,
               PULONG bytes_transferred, FSP_FSCTL_FILE_INFO* file_info)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (!self || !self->backend_ || !context)
		return STATUS_DEVICE_NOT_CONNECTED;
	if (context->is_directory)
		return STATUS_FILE_IS_A_DIRECTORY;
	if (bytes_transferred)
		*bytes_transferred = 0;

	if (write_to_end_of_file || constrained_io)
	{
		auto standard =
		    self->backend_->QueryInformation(context->handle, FileStandardInformation,
		                                     std::chrono::milliseconds(5000));
		if (standard.error == RdpdrError::Ok && standard.payload.size() >= 16)
		{
			std::uint64_t end_of_file = 0;
			std::memcpy(&end_of_file, standard.payload.data() + 8, sizeof(end_of_file));
			if (write_to_end_of_file)
				offset = end_of_file;
			if (constrained_io && offset >= end_of_file)
				return STATUS_SUCCESS;
			if (constrained_io && offset + length > end_of_file)
				length = static_cast<ULONG>(end_of_file - offset);
		}
	}

	std::vector<std::uint8_t> data(static_cast<std::uint8_t*>(buffer),
	                               static_cast<std::uint8_t*>(buffer) + length);
	auto result =
	    self->backend_->WriteFile(context->handle, offset, data, std::chrono::milliseconds(5000));
	if (result.error != RdpdrError::Ok)
		return MapStatus(result.error);
	if (bytes_transferred)
		*bytes_transferred = result.bytes_written;

	if (file_info)
	{
		MappedPath mapped{ false, context->device_id, context->remote_path };
		FillFileInfoForMapping(self->backend_, mapped, file_info);
	}
	return STATUS_SUCCESS;
}

NTSTATUS Flush(FSP_FILE_SYSTEM*, PVOID, FSP_FSCTL_FILE_INFO*)
{
	return STATUS_SUCCESS;
}

NTSTATUS GetFileInfo(FSP_FILE_SYSTEM* file_system, PVOID file_context,
                     FSP_FSCTL_FILE_INFO* file_info)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (!self || !self->backend_ || !context)
		return STATUS_DEVICE_NOT_CONNECTED;
	if (context->device_id == 0 && context->remote_path == "\\")
	{
		std::memset(file_info, 0, sizeof(*file_info));
		file_info->FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
		return STATUS_SUCCESS;
	}
	MappedPath mapped{ false, context->device_id, context->remote_path };
	return FillFileInfoForMapping(self->backend_, mapped, file_info);
}

NTSTATUS SetBasicInfo(FSP_FILE_SYSTEM* file_system, PVOID file_context, UINT32 file_attributes,
                      UINT64 creation_time, UINT64 last_access_time, UINT64 last_write_time,
                      UINT64 change_time, FSP_FSCTL_FILE_INFO* file_info)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (!self || !self->backend_ || !context)
		return STATUS_DEVICE_NOT_CONNECTED;

	std::vector<std::uint8_t> basic(36, 0);
	std::memcpy(basic.data(), &creation_time, sizeof(creation_time));
	std::memcpy(basic.data() + 8, &last_access_time, sizeof(last_access_time));
	std::memcpy(basic.data() + 16, &last_write_time, sizeof(last_write_time));
	std::memcpy(basic.data() + 24, &change_time, sizeof(change_time));
	std::memcpy(basic.data() + 32, &file_attributes, sizeof(file_attributes));

	FileHandle handle = context->handle;
	bool close_after = false;
	if (!context->has_handle)
	{
		auto open =
		    self->backend_->OpenFile(context->device_id, context->remote_path, FILE_WRITE_ATTRIBUTES,
		                             FILE_OPEN, std::chrono::milliseconds(5000));
		if (open.error != RdpdrError::Ok)
			return MapStatus(open.error);
		handle = open.handle;
		close_after = true;
	}

	auto result = self->backend_->SetInformation(handle, FileBasicInformation, basic,
	                                            std::chrono::milliseconds(5000));
	if (close_after)
		self->backend_->CloseFile(handle, std::chrono::milliseconds(5000));
	if (result.error != RdpdrError::Ok)
		return MapStatus(result.error);

	if (file_info)
	{
		MappedPath mapped{ false, context->device_id, context->remote_path };
		FillFileInfoForMapping(self->backend_, mapped, file_info);
	}
	return STATUS_SUCCESS;
}

NTSTATUS SetFileSize(FSP_FILE_SYSTEM* file_system, PVOID file_context, UINT64 size, BOOLEAN,
                     FSP_FSCTL_FILE_INFO* file_info)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (!self || !self->backend_ || !context)
		return STATUS_DEVICE_NOT_CONNECTED;
	if (!context->has_handle || context->is_directory)
		return STATUS_FILE_IS_A_DIRECTORY;

	std::vector<std::uint8_t> payload(sizeof(size));
	std::memcpy(payload.data(), &size, sizeof(size));
	FileHandle handle = context->handle;
	bool close_after = false;
	if (!context->has_handle)
	{
		auto open =
		    self->backend_->OpenFile(context->device_id, context->remote_path, FILE_WRITE_DATA,
		                             FILE_OPEN, std::chrono::milliseconds(5000));
		if (open.error != RdpdrError::Ok)
			return MapStatus(open.error);
		handle = open.handle;
		close_after = true;
	}

	auto result = self->backend_->SetInformation(handle, FileEndOfFileInformation,
	                                            payload, std::chrono::milliseconds(5000));
	if (close_after)
		self->backend_->CloseFile(handle, std::chrono::milliseconds(5000));
	if (result.error != RdpdrError::Ok)
		return MapStatus(result.error);

	if (file_info)
	{
		MappedPath mapped{ false, context->device_id, context->remote_path };
		FillFileInfoForMapping(self->backend_, mapped, file_info);
	}
	return STATUS_SUCCESS;
}

NTSTATUS CanDelete(FSP_FILE_SYSTEM*, PVOID file_context, PWSTR)
{
	return file_context ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS Rename(FSP_FILE_SYSTEM* file_system, PVOID file_context, PWSTR file_name, PWSTR new_name,
                BOOLEAN)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	auto* context = static_cast<FileContext*>(file_context);
	if (!self || !self->backend_ || !context)
		return STATUS_DEVICE_NOT_CONNECTED;

	std::vector<DriveInfo> drives;
	{
		std::lock_guard<std::mutex> lock(self->drives_mutex_);
		drives = self->drives_;
	}
	auto mapped = MapFileName(drives, new_name);
	if (mapped.device_id == 0)
		return STATUS_OBJECT_NAME_NOT_FOUND;
	if (mapped.device_id != context->device_id)
		return STATUS_NOT_SAME_DEVICE;

	auto result = self->backend_->RenameFile(context->device_id, context->remote_path,
	                                        mapped.remote_path, std::chrono::milliseconds(5000));
	if (result.error != RdpdrError::Ok)
		return MapStatus(result.error);
	context->remote_path = mapped.remote_path;
	WINPR_UNUSED(file_name);
	return STATUS_SUCCESS;
}

NTSTATUS GetSecurity(FSP_FILE_SYSTEM*, PVOID, PSECURITY_DESCRIPTOR, PSIZE_T)
{
	return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS SetSecurity(FSP_FILE_SYSTEM*, PVOID, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR)
{
	return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS ReadDirectory(FSP_FILE_SYSTEM* file_system, PVOID, PWSTR file_name, PWSTR marker,
                       PVOID buffer, ULONG length, PULONG bytes_transferred)
{
	auto* self = static_cast<WinFspFrontend*>(file_system->UserContext);
	if (!self || !self->backend_)
		return STATUS_DEVICE_NOT_CONNECTED;
	if (bytes_transferred)
		*bytes_transferred = 0;

	std::vector<DriveInfo> drives;
	{
		std::lock_guard<std::mutex> lock(self->drives_mutex_);
		drives = self->drives_;
	}

	auto mapped = MapFileName(drives, file_name);
	std::vector<DirectoryEntry> entries;
	DirectoryEntry dot;
	dot.name = ".";
	dot.attributes = FILE_ATTRIBUTE_DIRECTORY;
	dot.is_directory = true;
	entries.push_back(dot);
	DirectoryEntry dotdot = dot;
	dotdot.name = "..";
	entries.push_back(dotdot);
	if (mapped.is_root)
	{
		for (const auto& drive : drives)
		{
			DirectoryEntry entry;
			entry.name = drive.dos_name;
			entry.attributes = FILE_ATTRIBUTE_DIRECTORY;
			entry.is_directory = true;
			entries.push_back(std::move(entry));
		}
	}
	else
	{
		if (mapped.device_id == 0)
			return STATUS_OBJECT_NAME_NOT_FOUND;
		auto result = self->backend_->QueryDirectory(mapped.device_id, mapped.remote_path,
		                                            std::chrono::milliseconds(5000));
		if (result.error != RdpdrError::Ok)
			return MapStatus(result.error);
		entries = std::move(result.entries);
	}

	auto marker_w = marker ? std::wstring(marker) : std::wstring();
	bool past_marker = marker_w.empty();

	ULONG bytes = 0;
	for (const auto& entry : entries)
	{
		auto name_w = Utf8ToWide(entry.name);
		if (!past_marker)
		{
			if (_wcsicmp(name_w.c_str(), marker_w.c_str()) <= 0)
				continue;
			past_marker = true;
		}

		const size_t name_bytes = sizeof(WCHAR) * name_w.size();
		const size_t info_size =
		    FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + name_bytes;
		std::vector<std::uint8_t> info_buf(info_size);
		auto* dirinfo = reinterpret_cast<FSP_FSCTL_DIR_INFO*>(info_buf.data());
		std::memset(dirinfo, 0, info_buf.size());

		dirinfo->Size = static_cast<UINT16>(info_size);
		dirinfo->FileInfo.FileAttributes = entry.attributes;
		dirinfo->FileInfo.FileSize = entry.size;
		dirinfo->FileInfo.AllocationSize = entry.size;
		dirinfo->FileInfo.CreationTime = entry.creation_time;
		dirinfo->FileInfo.LastAccessTime = entry.last_access_time;
		dirinfo->FileInfo.LastWriteTime = entry.last_write_time;
		dirinfo->FileInfo.ChangeTime = entry.last_write_time;
		dirinfo->FileInfo.ReparseTag = 0;
		dirinfo->FileInfo.IndexNumber = 0;
		dirinfo->FileInfo.HardLinks = 1;

		std::memcpy(dirinfo->FileNameBuf, name_w.data(), name_bytes);

		if (!FspFileSystemAddDirInfo(dirinfo, buffer, length, &bytes))
			break;
	}

	if (bytes_transferred)
		*bytes_transferred = bytes;
	return STATUS_SUCCESS;
}

} // namespace

#endif

bool WinFspFrontend::StartMount()
{
	if (mounted_)
		return true;
#if defined(_WIN32) && defined(TSCLIENT_WITH_WINFSP)
	if (file_system_)
		return true;

	FSP_FSCTL_VOLUME_PARAMS volume_params = {};
	volume_params.SectorSize = 512;
	volume_params.SectorsPerAllocationUnit = 8;
	volume_params.MaxComponentLength = 255;
	volume_params.CaseSensitiveSearch = 0;
	volume_params.CasePreservedNames = 1;
	volume_params.UnicodeOnDisk = 1;
	volume_params.PersistentAcls = 0;
	volume_params.PostCleanupWhenModifiedOnly = 1;
	volume_params.UmFileContextIsUserContext2 = 1;
	std::memcpy(volume_params.FileSystemName, L"TSCLIENT",
	            sizeof(L"TSCLIENT") - sizeof(wchar_t));

	FSP_FILE_SYSTEM_INTERFACE interface_ops = {};
	interface_ops.GetVolumeInfo = GetVolumeInfo;
	interface_ops.SetVolumeLabel = SetVolumeLabel;
	interface_ops.GetSecurityByName = GetSecurityByName;
	interface_ops.Create = Create;
	interface_ops.Open = Open;
	interface_ops.Overwrite = Overwrite;
	interface_ops.Cleanup = Cleanup;
	interface_ops.Close = Close;
	interface_ops.Read = Read;
	interface_ops.Write = Write;
	interface_ops.Flush = Flush;
	interface_ops.GetFileInfo = GetFileInfo;
	interface_ops.SetBasicInfo = SetBasicInfo;
	interface_ops.SetFileSize = SetFileSize;
	interface_ops.CanDelete = CanDelete;
	interface_ops.Rename = Rename;
	interface_ops.GetSecurity = GetSecurity;
	interface_ops.SetSecurity = SetSecurity;
	interface_ops.ReadDirectory = ReadDirectory;

	std::wstring mount_point = NormalizeMountPoint(Utf8ToWide(mount_point_));
	if (!mount_point.empty() && !IsDriveLetterMount(mount_point))
	{
		wchar_t full_path[MAX_PATH] = {};
		DWORD size = GetFullPathNameW(mount_point.c_str(), MAX_PATH, full_path, nullptr);
		if (size > 0 && size < MAX_PATH)
			mount_point.assign(full_path);
	}
	if (!mount_point.empty() && !IsDriveLetterMount(mount_point))
	{
		if (!EnsureDirectoryMount(mount_point))
		{
			WLog_Print(WLog_Get(TAG), WLOG_ERROR,
			           "Failed to create mount directory: %ls", mount_point.c_str());
			FspFileSystemDelete(file_system_);
			file_system_ = nullptr;
			return false;
		}
	}
	NTSTATUS status =
	    FspFileSystemCreate(L"" FSP_FSCTL_DISK_DEVICE_NAME, &volume_params, &interface_ops,
	                        &file_system_);
	if (!NT_SUCCESS(status))
	{
		WLog_Print(WLog_Get(TAG), WLOG_ERROR, "FspFileSystemCreate failed: 0x%08x",
		           static_cast<unsigned>(status));
		file_system_ = nullptr;
		return false;
	}

	file_system_->UserContext = this;
	status = FspFileSystemSetMountPoint(file_system_, mount_point.c_str());
	if (!NT_SUCCESS(status))
	{
		WLog_Print(WLog_Get(TAG), WLOG_ERROR, "FspFileSystemSetMountPoint failed: 0x%08x",
		           static_cast<unsigned>(status));
		FspFileSystemDelete(file_system_);
		file_system_ = nullptr;
		return false;
	}

	status = FspFileSystemStartDispatcher(file_system_, 0);
	if (!NT_SUCCESS(status))
	{
		WLog_Print(WLog_Get(TAG), WLOG_ERROR, "FspFileSystemStartDispatcher failed: 0x%08x",
		           static_cast<unsigned>(status));
		FspFileSystemDelete(file_system_);
		file_system_ = nullptr;
		return false;
	}

	mounted_ = true;
	return true;
#else
	WLog_Print(WLog_Get(TAG), WLOG_WARN,
	           "WinFsp frontend not available on this platform/build.");
	return false;
#endif
}

void WinFspFrontend::StopMount()
{
#if defined(_WIN32) && defined(TSCLIENT_WITH_WINFSP)
	if (file_system_)
	{
		FspFileSystemStopDispatcher(file_system_);
		FspFileSystemDelete(file_system_);
		file_system_ = nullptr;
	}
#endif
	mounted_ = false;
}

void WinFspFrontend::UpdateDriveList(const std::vector<DriveInfo>& drives)
{
	std::lock_guard<std::mutex> lock(drives_mutex_);
	drives_ = drives;
}

} // namespace tsclient
