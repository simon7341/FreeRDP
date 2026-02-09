#include "rdpdr_backend.h"

#include <cstring>

#include <freerdp/channels/rdpdr.h>
#include <winpr/nt.h>
#include <winpr/crt.h>
#include <winpr/file.h>

namespace tsclient
{

namespace
{
constexpr std::uint32_t kDefaultFileAccess = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
}

RdpdrBackend::RdpdrBackend(IRdpdrTransport* transport) : transport_(transport), next_completion_id_(1)
{
	if (transport_)
	{
		transport_->RegisterCompletionCallback(
		    [this](std::uint32_t completion_id, RdpdrError error, std::vector<std::uint8_t> payload) {
			    OnTransportCompletion(completion_id, error, std::move(payload));
		    });
	}
}

RdpdrBackend::~RdpdrBackend()
{
	CancelAll(RdpdrError::Cancelled);
}

void RdpdrBackend::AttachServerContext(RdpdrServerContext* context)
{
	server_context_ = context;
	if (!server_context_)
		return;
	server_context_->data = this;
	server_context_->supported = RDPDR_DTYP_FILESYSTEM;
	server_context_->OnDriveCreate = OnDriveCreate;
	server_context_->OnDriveDelete = OnDriveDelete;
	server_context_->OnDriveOpenFileComplete = OnDriveOpenFileComplete;
	server_context_->OnDriveReadFileComplete = OnDriveReadFileComplete;
	server_context_->OnDriveWriteFileComplete = OnDriveWriteFileComplete;
	server_context_->OnDriveCloseFileComplete = OnDriveCloseFileComplete;
	server_context_->OnDriveDeleteFileComplete = OnDriveDeleteFileComplete;
	server_context_->OnDriveRenameFileComplete = OnDriveRenameFileComplete;
	server_context_->OnDriveCreateDirectoryComplete = OnDriveCreateDirectoryComplete;
	server_context_->OnDriveDeleteDirectoryComplete = OnDriveDeleteDirectoryComplete;
	server_context_->OnDriveQueryDirectoryComplete = OnDriveQueryDirectoryComplete;
	server_context_->OnDriveQueryInformationComplete = OnDriveQueryInformationComplete;
	server_context_->OnDriveQueryVolumeInformationComplete = OnDriveQueryVolumeInformationComplete;
}

void RdpdrBackend::DetachServerContext()
{
	server_context_ = nullptr;
}

void RdpdrBackend::SetDriveListCallback(std::function<void(const std::vector<DriveInfo>&)> cb)
{
	drive_list_callback_ = std::move(cb);
}

void RdpdrBackend::UpdateDrives(const std::vector<DriveInfo>& drives)
{
	std::lock_guard<std::mutex> lock(mutex_);
	drives_ = drives;
}

void RdpdrBackend::OnTransportCompletion(std::uint32_t completion_id, RdpdrError error,
                                         std::vector<std::uint8_t> payload)
{
	std::promise<RdpdrResult> promise;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = pending_.find(completion_id);
		if (it == pending_.end())
			return;
		promise = std::move(it->second.promise);
		pending_.erase(it);
	}
	promise.set_value(RdpdrResult{ error, std::move(payload) });
}

void RdpdrBackend::CancelAll(RdpdrError error)
{
	std::unordered_map<std::uint32_t, PendingRequest> pending;
	std::unordered_map<PendingBase*, std::unique_ptr<PendingBase>> pending_ops;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		pending.swap(pending_);
		pending_ops.swap(pending_ops_);
	}
	for (auto& entry : pending)
		entry.second.promise.set_value(RdpdrResult{ error, {} });

	for (auto& entry : pending_ops)
	{
		if (!entry.first->completed.exchange(true))
		{
			// Best-effort: complete with cancellation depending on type.
			if (auto* open = dynamic_cast<PendingOpen*>(entry.first))
				open->promise.set_value(OpenResult{ error, {} });
			else if (auto* read = dynamic_cast<PendingRead*>(entry.first))
				read->promise.set_value(ReadResult{ error, {} });
			else if (auto* write = dynamic_cast<PendingWrite*>(entry.first))
				write->promise.set_value(WriteResult{ error, 0 });
			else if (auto* dir = dynamic_cast<PendingQueryDirectory*>(entry.first))
				dir->promise.set_value(QueryDirectoryResult{ error, {} });
		}
	}
}

OpenResult RdpdrBackend::OpenFile(std::uint32_t device_id, const std::string& remote_path,
                                 std::uint32_t desired_access, std::uint32_t create_disposition,
                                 std::chrono::milliseconds timeout)
{
	if (server_context_)
	{
		auto pending = std::make_unique<PendingOpen>();
		auto* pending_ptr = pending.get();
		RegisterPending(pending_ptr);
		if (server_context_->DriveOpenFile(server_context_, pending_ptr, device_id,
		                                   remote_path.c_str(),
		                                   desired_access ? desired_access : kDefaultFileAccess,
		                                   create_disposition) != CHANNEL_RC_OK)
		{
			UnregisterPending(pending_ptr);
			return { RdpdrError::TransportError, {} };
		}
		auto future = pending_ptr->promise.get_future();
		if (future.wait_for(timeout) == std::future_status::timeout)
		{
			pending_ptr->completed.exchange(true);
			return { RdpdrError::Timeout, {} };
		}
		return future.get();
	}

	return { RdpdrError::NotConnected, {} };
}

RdpdrResult RdpdrBackend::CloseFile(const FileHandle& handle, std::chrono::milliseconds timeout)
{
	if (server_context_)
	{
		auto pending = std::make_unique<PendingWrite>();
		auto* pending_ptr = pending.get();
		RegisterPending(pending_ptr);
		if (server_context_->DriveCloseFile(server_context_, pending_ptr, handle.device_id,
		                                   handle.file_id) != CHANNEL_RC_OK)
		{
			UnregisterPending(pending_ptr);
			return { RdpdrError::TransportError, {} };
		}
		auto future = pending_ptr->promise.get_future();
		if (future.wait_for(timeout) == std::future_status::timeout)
		{
			pending_ptr->completed.exchange(true);
			return { RdpdrError::Timeout, {} };
		}
		const auto result = future.get();
		return { result.error, {} };
	}
	return { RdpdrError::NotConnected, {} };
}

ReadResult RdpdrBackend::ReadFile(const FileHandle& handle, std::uint64_t offset,
                                 std::uint32_t length, std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, {} };

	std::vector<std::uint8_t> full;
	std::uint64_t current_offset = offset;
	std::uint32_t remaining = length;
	while (remaining > 0)
	{
		const std::uint32_t chunk = remaining > max_chunk_size_ ? max_chunk_size_ : remaining;
		auto pending = std::make_unique<PendingRead>();
		auto* pending_ptr = pending.get();
		RegisterPending(pending_ptr);
		if (server_context_->DriveReadFile(server_context_, pending_ptr, handle.device_id,
		                                  handle.file_id, chunk,
		                                  static_cast<UINT32>(current_offset)) != CHANNEL_RC_OK)
		{
			UnregisterPending(pending_ptr);
			return { RdpdrError::TransportError, {} };
		}
		auto future = pending_ptr->promise.get_future();
		if (future.wait_for(timeout) == std::future_status::timeout)
		{
			pending_ptr->completed.exchange(true);
			return { RdpdrError::Timeout, {} };
		}
		auto result = future.get();
		if (result.error != RdpdrError::Ok)
			return result;
		full.insert(full.end(), result.data.begin(), result.data.end());
		current_offset += chunk;
		remaining -= chunk;
		if (result.data.size() < chunk)
			break;
	}
	return { RdpdrError::Ok, std::move(full) };
}

WriteResult RdpdrBackend::WriteFile(const FileHandle& handle, std::uint64_t offset,
                                   const std::vector<std::uint8_t>& data,
                                   std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, 0 };

	std::uint64_t current_offset = offset;
	std::uint32_t remaining = static_cast<std::uint32_t>(data.size());
	std::uint32_t cursor = 0;
	std::uint32_t total_written = 0;
	while (remaining > 0)
	{
		const std::uint32_t chunk = remaining > max_chunk_size_ ? max_chunk_size_ : remaining;
		auto pending = std::make_unique<PendingWrite>();
		auto* pending_ptr = pending.get();
		RegisterPending(pending_ptr);
		if (server_context_->DriveWriteFile(
		        server_context_, pending_ptr, handle.device_id, handle.file_id,
		        reinterpret_cast<const char*>(data.data() + cursor), chunk,
		        static_cast<UINT32>(current_offset)) != CHANNEL_RC_OK)
		{
			UnregisterPending(pending_ptr);
			return { RdpdrError::TransportError, total_written };
		}
		auto future = pending_ptr->promise.get_future();
		if (future.wait_for(timeout) == std::future_status::timeout)
		{
			pending_ptr->completed.exchange(true);
			return { RdpdrError::Timeout, total_written };
		}
		auto result = future.get();
		if (result.error != RdpdrError::Ok)
			return { result.error, total_written };
		total_written += result.bytes_written;
		current_offset += chunk;
		cursor += chunk;
		remaining -= chunk;
	}
	return { RdpdrError::Ok, total_written };
}

QueryDirectoryResult RdpdrBackend::QueryDirectory(std::uint32_t device_id,
                                                  const std::string& remote_path,
                                                  std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, {} };

	auto pending = std::make_unique<PendingQueryDirectory>();
	auto* pending_ptr = pending.get();
	RegisterPending(pending_ptr);
	if (server_context_->DriveQueryDirectory(server_context_, pending_ptr, device_id,
	                                        remote_path.c_str()) != CHANNEL_RC_OK)
	{
		UnregisterPending(pending_ptr);
		return { RdpdrError::TransportError, {} };
	}
	auto future = pending_ptr->promise.get_future();
	if (future.wait_for(timeout) == std::future_status::timeout)
	{
		pending_ptr->completed.exchange(true);
		return { RdpdrError::Timeout, {} };
	}
	return future.get();
}

QueryInfoResult RdpdrBackend::QueryInformation(const FileHandle& handle, std::uint32_t info_class,
                                              std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, {} };

	auto pending = std::make_unique<PendingQueryInfo>();
	auto* pending_ptr = pending.get();
	RegisterPending(pending_ptr);
	if (server_context_->DriveQueryInformation(server_context_, pending_ptr, handle.device_id,
	                                          handle.file_id, info_class) != CHANNEL_RC_OK)
	{
		UnregisterPending(pending_ptr);
		return { RdpdrError::TransportError, {} };
	}
	auto future = pending_ptr->promise.get_future();
	if (future.wait_for(timeout) == std::future_status::timeout)
	{
		pending_ptr->completed.exchange(true);
		return { RdpdrError::Timeout, {} };
	}
	return future.get();
}

QueryInfoResult RdpdrBackend::QueryVolumeInformation(std::uint32_t device_id, std::uint32_t info_class,
                                                    std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, {} };

	auto pending = std::make_unique<PendingQueryInfo>();
	auto* pending_ptr = pending.get();
	RegisterPending(pending_ptr);
	if (server_context_->DriveQueryVolumeInformation(server_context_, pending_ptr, device_id,
	                                                info_class) != CHANNEL_RC_OK)
	{
		UnregisterPending(pending_ptr);
		return { RdpdrError::TransportError, {} };
	}
	auto future = pending_ptr->promise.get_future();
	if (future.wait_for(timeout) == std::future_status::timeout)
	{
		pending_ptr->completed.exchange(true);
		return { RdpdrError::Timeout, {} };
	}
	return future.get();
}

RdpdrResult RdpdrBackend::CreateDirectory(std::uint32_t device_id, const std::string& remote_path,
                                         std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, {} };

	auto pending = std::make_unique<PendingWrite>();
	auto* pending_ptr = pending.get();
	RegisterPending(pending_ptr);
	if (server_context_->DriveCreateDirectory(server_context_, pending_ptr, device_id,
	                                         remote_path.c_str()) != CHANNEL_RC_OK)
	{
		UnregisterPending(pending_ptr);
		return { RdpdrError::TransportError, {} };
	}
	auto future = pending_ptr->promise.get_future();
	if (future.wait_for(timeout) == std::future_status::timeout)
	{
		pending_ptr->completed.exchange(true);
		return { RdpdrError::Timeout, {} };
	}
	const auto result = future.get();
	return { result.error, {} };
}

RdpdrResult RdpdrBackend::DeleteDirectory(std::uint32_t device_id, const std::string& remote_path,
                                         std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, {} };

	auto pending = std::make_unique<PendingWrite>();
	auto* pending_ptr = pending.get();
	RegisterPending(pending_ptr);
	if (server_context_->DriveDeleteDirectory(server_context_, pending_ptr, device_id,
	                                         remote_path.c_str()) != CHANNEL_RC_OK)
	{
		UnregisterPending(pending_ptr);
		return { RdpdrError::TransportError, {} };
	}
	auto future = pending_ptr->promise.get_future();
	if (future.wait_for(timeout) == std::future_status::timeout)
	{
		pending_ptr->completed.exchange(true);
		return { RdpdrError::Timeout, {} };
	}
	const auto result = future.get();
	return { result.error, {} };
}

RdpdrResult RdpdrBackend::DeleteFile(std::uint32_t device_id, const std::string& remote_path,
                                    std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, {} };

	auto pending = std::make_unique<PendingWrite>();
	auto* pending_ptr = pending.get();
	RegisterPending(pending_ptr);
	if (server_context_->DriveDeleteFile(server_context_, pending_ptr, device_id,
	                                    remote_path.c_str()) != CHANNEL_RC_OK)
	{
		UnregisterPending(pending_ptr);
		return { RdpdrError::TransportError, {} };
	}
	auto future = pending_ptr->promise.get_future();
	if (future.wait_for(timeout) == std::future_status::timeout)
	{
		pending_ptr->completed.exchange(true);
		return { RdpdrError::Timeout, {} };
	}
	const auto result = future.get();
	return { result.error, {} };
}

RdpdrResult RdpdrBackend::RenameFile(std::uint32_t device_id, const std::string& old_path,
                                    const std::string& new_path,
                                    std::chrono::milliseconds timeout)
{
	if (!server_context_)
		return { RdpdrError::NotConnected, {} };

	auto pending = std::make_unique<PendingWrite>();
	auto* pending_ptr = pending.get();
	RegisterPending(pending_ptr);
	if (server_context_->DriveRenameFile(server_context_, pending_ptr, device_id, old_path.c_str(),
	                                    new_path.c_str()) != CHANNEL_RC_OK)
	{
		UnregisterPending(pending_ptr);
		return { RdpdrError::TransportError, {} };
	}
	auto future = pending_ptr->promise.get_future();
	if (future.wait_for(timeout) == std::future_status::timeout)
	{
		pending_ptr->completed.exchange(true);
		return { RdpdrError::Timeout, {} };
	}
	const auto result = future.get();
	return { result.error, {} };
}

RdpdrResult RdpdrBackend::SendRequestAndWait(const std::vector<std::uint8_t>& packet,
                                            std::chrono::milliseconds timeout)
{
	if (!transport_)
		return { RdpdrError::NotConnected, {} };

	const std::uint32_t completion_id = next_completion_id_.fetch_add(1);
	std::promise<RdpdrResult> promise;
	auto future = promise.get_future();
	{
		std::lock_guard<std::mutex> lock(mutex_);
		pending_.emplace(completion_id, PendingRequest{ std::move(promise) });
	}

	if (!transport_->SendDeviceIoRequest(packet))
	{
		std::lock_guard<std::mutex> lock(mutex_);
		pending_.erase(completion_id);
		return { RdpdrError::TransportError, {} };
	}

	if (future.wait_for(timeout) == std::future_status::timeout)
	{
		std::lock_guard<std::mutex> lock(mutex_);
		pending_.erase(completion_id);
		return { RdpdrError::Timeout, {} };
	}
	return future.get();
}

void RdpdrBackend::RegisterPending(PendingBase* pending)
{
	std::lock_guard<std::mutex> lock(mutex_);
	RegisterPendingLocked(pending);
}

void RdpdrBackend::RegisterPendingLocked(PendingBase* pending)
{
	pending_ops_.emplace(pending, std::unique_ptr<PendingBase>(pending));
}

void RdpdrBackend::UnregisterPending(PendingBase* pending)
{
	std::lock_guard<std::mutex> lock(mutex_);
	UnregisterPendingLocked(pending);
}

void RdpdrBackend::UnregisterPendingLocked(PendingBase* pending)
{
	pending_ops_.erase(pending);
}

RdpdrError RdpdrBackend::MapStatusToError(std::uint32_t status) const
{
	if (status == STATUS_SUCCESS || status == STATUS_NO_MORE_FILES)
		return RdpdrError::Ok;
	if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_NO_SUCH_FILE)
		return RdpdrError::NotFound;
	if (status == STATUS_ACCESS_DENIED)
		return RdpdrError::AccessDenied;
	if (status == STATUS_SHARING_VIOLATION)
		return RdpdrError::Busy;
	return RdpdrError::IoError;
}

UINT RdpdrBackend::OnDriveCreate(RdpdrServerContext* context, const RdpdrDevice* device)
{
	if (!context || !device)
		return CHANNEL_RC_OK;
	if (device->DeviceType != RDPDR_DTYP_FILESYSTEM)
		return CHANNEL_RC_OK;
	auto* backend = static_cast<RdpdrBackend*>(context->data);
	if (!backend)
		return CHANNEL_RC_OK;

	std::vector<DriveInfo> drives;
	{
		std::lock_guard<std::mutex> lock(backend->mutex_);
		drives = backend->drives_;
	}
	DriveInfo info;
	info.device_id = device->DeviceId;
	info.dos_name = device->PreferredDosName;
	drives.push_back(std::move(info));
	backend->UpdateDrives(drives);
	if (backend->drive_list_callback_)
		backend->drive_list_callback_(drives);
	return CHANNEL_RC_OK;
}

UINT RdpdrBackend::OnDriveDelete(RdpdrServerContext* context, UINT32 deviceId)
{
	auto* backend = static_cast<RdpdrBackend*>(context ? context->data : nullptr);
	if (!backend)
		return CHANNEL_RC_OK;
	std::vector<DriveInfo> drives;
	{
		std::lock_guard<std::mutex> lock(backend->mutex_);
		for (const auto& drive : backend->drives_)
		{
			if (drive.device_id != deviceId)
				drives.push_back(drive);
		}
		backend->drives_ = drives;
	}
	if (backend->drive_list_callback_)
		backend->drive_list_callback_(drives);
	return CHANNEL_RC_OK;
}

void RdpdrBackend::OnDriveOpenFileComplete(RdpdrServerContext* context, void* callbackData,
                                          UINT32 ioStatus, UINT32 deviceId, UINT32 fileId)
{
	auto* backend = static_cast<RdpdrBackend*>(context ? context->data : nullptr);
	auto* pending = static_cast<PendingOpen*>(callbackData);
	if (!backend || !pending)
		return;

	if (!pending->completed.exchange(true))
		pending->promise.set_value(OpenResult{ backend->MapStatusToError(ioStatus),
		                                       FileHandle{ deviceId, fileId } });
	backend->UnregisterPending(pending);
}

void RdpdrBackend::OnDriveReadFileComplete(RdpdrServerContext* context, void* callbackData,
                                          UINT32 ioStatus, const char* buffer, UINT32 length)
{
	auto* backend = static_cast<RdpdrBackend*>(context ? context->data : nullptr);
	auto* pending = static_cast<PendingRead*>(callbackData);
	if (!backend || !pending)
		return;

	ReadResult result;
	result.error = backend->MapStatusToError(ioStatus);
	if (result.error == RdpdrError::Ok && buffer && length > 0)
		result.data.assign(buffer, buffer + length);

	if (!pending->completed.exchange(true))
		pending->promise.set_value(std::move(result));
	backend->UnregisterPending(pending);
}

void RdpdrBackend::OnDriveWriteFileComplete(RdpdrServerContext* context, void* callbackData,
                                           UINT32 ioStatus, UINT32 bytesWritten)
{
	auto* backend = static_cast<RdpdrBackend*>(context ? context->data : nullptr);
	auto* pending = static_cast<PendingWrite*>(callbackData);
	if (!backend || !pending)
		return;

	WriteResult result{ backend->MapStatusToError(ioStatus), bytesWritten };
	if (!pending->completed.exchange(true))
		pending->promise.set_value(result);
	backend->UnregisterPending(pending);
}

void RdpdrBackend::OnDriveCloseFileComplete(RdpdrServerContext* context, void* callbackData,
                                           UINT32 ioStatus)
{
	auto* backend = static_cast<RdpdrBackend*>(context ? context->data : nullptr);
	auto* pending = static_cast<PendingWrite*>(callbackData);
	if (!backend || !pending)
		return;

	WriteResult result{ backend->MapStatusToError(ioStatus), 0 };
	if (!pending->completed.exchange(true))
		pending->promise.set_value(result);
	backend->UnregisterPending(pending);
}

void RdpdrBackend::OnDriveDeleteFileComplete(RdpdrServerContext* context, void* callbackData,
                                            UINT32 ioStatus)
{
	OnDriveCloseFileComplete(context, callbackData, ioStatus);
}

void RdpdrBackend::OnDriveRenameFileComplete(RdpdrServerContext* context, void* callbackData,
                                            UINT32 ioStatus)
{
	OnDriveCloseFileComplete(context, callbackData, ioStatus);
}

void RdpdrBackend::OnDriveCreateDirectoryComplete(RdpdrServerContext* context, void* callbackData,
                                                 UINT32 ioStatus)
{
	OnDriveCloseFileComplete(context, callbackData, ioStatus);
}

void RdpdrBackend::OnDriveDeleteDirectoryComplete(RdpdrServerContext* context, void* callbackData,
                                                 UINT32 ioStatus)
{
	OnDriveCloseFileComplete(context, callbackData, ioStatus);
}

void RdpdrBackend::OnDriveQueryDirectoryComplete(RdpdrServerContext* context, void* callbackData,
                                                UINT32 ioStatus, FILE_DIRECTORY_INFORMATION* fdi)
{
	auto* backend = static_cast<RdpdrBackend*>(context ? context->data : nullptr);
	auto* pending = static_cast<PendingQueryDirectory*>(callbackData);
	if (!backend || !pending)
		return;

	if (ioStatus == STATUS_SUCCESS && fdi)
	{
		DirectoryEntry entry;
		entry.name = fdi->FileName;
		entry.attributes = fdi->FileAttributes;
		entry.size = static_cast<std::uint64_t>(fdi->EndOfFile.QuadPart);
		entry.creation_time = static_cast<std::uint64_t>(fdi->CreationTime.QuadPart);
		entry.last_access_time = static_cast<std::uint64_t>(fdi->LastAccessTime.QuadPart);
		entry.last_write_time = static_cast<std::uint64_t>(fdi->LastWriteTime.QuadPart);
		entry.is_directory = (fdi->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
		pending->entries.push_back(std::move(entry));
		return;
	}

	QueryDirectoryResult result;
	result.error = backend->MapStatusToError(ioStatus);
	result.entries = std::move(pending->entries);
	if (!pending->completed.exchange(true))
		pending->promise.set_value(std::move(result));
	backend->UnregisterPending(pending);
}

void RdpdrBackend::OnDriveQueryInformationComplete(RdpdrServerContext* context, void* callbackData,
                                                  UINT32 ioStatus, const BYTE* buffer,
                                                  UINT32 length)
{
	auto* backend = static_cast<RdpdrBackend*>(context ? context->data : nullptr);
	auto* pending = static_cast<PendingQueryInfo*>(callbackData);
	if (!backend || !pending)
		return;

	QueryInfoResult result;
	result.error = backend->MapStatusToError(ioStatus);
	if (result.error == RdpdrError::Ok && buffer && length > 0)
		result.payload.assign(buffer, buffer + length);

	if (!pending->completed.exchange(true))
		pending->promise.set_value(std::move(result));
	backend->UnregisterPending(pending);
}

void RdpdrBackend::OnDriveQueryVolumeInformationComplete(RdpdrServerContext* context,
                                                        void* callbackData, UINT32 ioStatus,
                                                        const BYTE* buffer, UINT32 length)
{
	OnDriveQueryInformationComplete(context, callbackData, ioStatus, buffer, length);
}

} // namespace tsclient
