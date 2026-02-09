#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

#include <freerdp/server/rdpdr.h>

#include "rdpdr_transport.h"

namespace tsclient
{

struct FileHandle
{
	std::uint32_t device_id = 0;
	std::uint32_t file_id = 0;
};

struct DirectoryEntry
{
	std::string name;
	std::uint32_t attributes = 0;
	std::uint64_t size = 0;
	std::uint64_t creation_time = 0;
	std::uint64_t last_access_time = 0;
	std::uint64_t last_write_time = 0;
	bool is_directory = false;
};

struct OpenResult
{
	RdpdrError error = RdpdrError::Ok;
	FileHandle handle;
};

struct ReadResult
{
	RdpdrError error = RdpdrError::Ok;
	std::vector<std::uint8_t> data;
};

struct WriteResult
{
	RdpdrError error = RdpdrError::Ok;
	std::uint32_t bytes_written = 0;
};

struct QueryDirectoryResult
{
	RdpdrError error = RdpdrError::Ok;
	std::vector<DirectoryEntry> entries;
};

struct QueryInfoResult
{
	RdpdrError error = RdpdrError::Ok;
	std::vector<std::uint8_t> payload;
};

class RdpdrBackend
{
  public:
	explicit RdpdrBackend(IRdpdrTransport* transport);
	~RdpdrBackend();

	void AttachServerContext(RdpdrServerContext* context);
	void DetachServerContext();

	void SetDriveListCallback(std::function<void(const std::vector<DriveInfo>&)> cb);
	void UpdateDrives(const std::vector<DriveInfo>& drives);
	void OnTransportCompletion(std::uint32_t completion_id, RdpdrError error,
	                           std::vector<std::uint8_t> payload);
	void CancelAll(RdpdrError error);

	OpenResult OpenFile(std::uint32_t device_id, const std::string& remote_path,
	                    std::uint32_t desired_access, std::uint32_t create_disposition,
	                    std::chrono::milliseconds timeout);
	RdpdrResult CloseFile(const FileHandle& handle, std::chrono::milliseconds timeout);
	ReadResult ReadFile(const FileHandle& handle, std::uint64_t offset, std::uint32_t length,
	                    std::chrono::milliseconds timeout);
	WriteResult WriteFile(const FileHandle& handle, std::uint64_t offset,
	                      const std::vector<std::uint8_t>& data,
	                      std::chrono::milliseconds timeout);
	QueryDirectoryResult QueryDirectory(std::uint32_t device_id, const std::string& remote_path,
	                                    std::chrono::milliseconds timeout);
	RdpdrResult CreateDirectory(std::uint32_t device_id, const std::string& remote_path,
	                            std::chrono::milliseconds timeout);
	RdpdrResult DeleteDirectory(std::uint32_t device_id, const std::string& remote_path,
	                            std::chrono::milliseconds timeout);
	RdpdrResult DeleteFile(std::uint32_t device_id, const std::string& remote_path,
	                       std::chrono::milliseconds timeout);
	RdpdrResult RenameFile(std::uint32_t device_id, const std::string& old_path,
	                       const std::string& new_path, std::chrono::milliseconds timeout);
	QueryInfoResult QueryInformation(const FileHandle& handle, std::uint32_t info_class,
	                                 std::chrono::milliseconds timeout);
	QueryInfoResult QueryVolumeInformation(std::uint32_t device_id, std::uint32_t info_class,
	                                       std::chrono::milliseconds timeout);

  private:
	struct PendingRequest
	{
		std::promise<RdpdrResult> promise;
	};

	struct PendingBase
	{
		std::atomic<bool> completed{ false };
		virtual ~PendingBase() = default;
	};

	struct PendingOpen final : PendingBase
	{
		std::promise<OpenResult> promise;
	};

	struct PendingRead final : PendingBase
	{
		std::promise<ReadResult> promise;
	};

	struct PendingWrite final : PendingBase
	{
		std::promise<WriteResult> promise;
	};

	struct PendingQueryDirectory final : PendingBase
	{
		std::promise<QueryDirectoryResult> promise;
		std::vector<DirectoryEntry> entries;
	};

	struct PendingQueryInfo final : PendingBase
	{
		std::promise<QueryInfoResult> promise;
	};

	RdpdrResult SendRequestAndWait(const std::vector<std::uint8_t>& packet,
	                               std::chrono::milliseconds timeout);

	void CompletePending(PendingBase* pending);
	void RegisterPending(PendingBase* pending);
	void RegisterPendingLocked(PendingBase* pending);
	void UnregisterPending(PendingBase* pending);
	void UnregisterPendingLocked(PendingBase* pending);
	RdpdrError MapStatusToError(std::uint32_t status) const;

	static UINT OnDriveCreate(RdpdrServerContext* context, const RdpdrDevice* device);
	static UINT OnDriveDelete(RdpdrServerContext* context, UINT32 deviceId);
	static void OnDriveOpenFileComplete(RdpdrServerContext* context, void* callbackData,
	                                    UINT32 ioStatus, UINT32 deviceId, UINT32 fileId);
	static void OnDriveReadFileComplete(RdpdrServerContext* context, void* callbackData,
	                                    UINT32 ioStatus, const char* buffer, UINT32 length);
	static void OnDriveWriteFileComplete(RdpdrServerContext* context, void* callbackData,
	                                     UINT32 ioStatus, UINT32 bytesWritten);
	static void OnDriveCloseFileComplete(RdpdrServerContext* context, void* callbackData,
	                                     UINT32 ioStatus);
	static void OnDriveDeleteFileComplete(RdpdrServerContext* context, void* callbackData,
	                                      UINT32 ioStatus);
	static void OnDriveRenameFileComplete(RdpdrServerContext* context, void* callbackData,
	                                      UINT32 ioStatus);
	static void OnDriveCreateDirectoryComplete(RdpdrServerContext* context, void* callbackData,
	                                           UINT32 ioStatus);
	static void OnDriveDeleteDirectoryComplete(RdpdrServerContext* context, void* callbackData,
	                                           UINT32 ioStatus);
	static void OnDriveQueryDirectoryComplete(RdpdrServerContext* context, void* callbackData,
	                                          UINT32 ioStatus,
	                                          FILE_DIRECTORY_INFORMATION* fdi);
	static void OnDriveQueryInformationComplete(RdpdrServerContext* context, void* callbackData,
	                                            UINT32 ioStatus, const BYTE* buffer, UINT32 length);
	static void OnDriveQueryVolumeInformationComplete(RdpdrServerContext* context,
	                                                  void* callbackData, UINT32 ioStatus,
	                                                  const BYTE* buffer, UINT32 length);

	IRdpdrTransport* transport_ = nullptr;
	RdpdrServerContext* server_context_ = nullptr;
	std::function<void(const std::vector<DriveInfo>&)> drive_list_callback_;
	std::atomic<std::uint32_t> next_completion_id_;
	std::mutex mutex_;
	std::unordered_map<std::uint32_t, PendingRequest> pending_;
	std::unordered_map<PendingBase*, std::unique_ptr<PendingBase>> pending_ops_;
	std::vector<DriveInfo> drives_;
	const std::uint32_t max_chunk_size_ = 1024 * 1024;
};

} // namespace tsclient
