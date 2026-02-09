#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "rdpdr_transport.h"

namespace tsclient
{

class RdpdrBackend;

class WinFspFrontend : public IFileSystemFrontend
{
  public:
	WinFspFrontend(RdpdrBackend* backend, std::string mount_point);

	bool StartMount() override;
	void StopMount() override;
	void UpdateDriveList(const std::vector<DriveInfo>& drives) override;

  private:
	RdpdrBackend* backend_ = nullptr;
	std::string mount_point_;
	std::mutex drives_mutex_;
	std::vector<DriveInfo> drives_;
	bool mounted_ = false;
#if defined(_WIN32)
	struct _FSP_FILE_SYSTEM* file_system_ = nullptr;
#endif
};

} // namespace tsclient
