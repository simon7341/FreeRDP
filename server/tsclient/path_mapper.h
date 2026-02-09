#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "rdpdr_transport.h"

namespace tsclient
{

struct RemotePath
{
	std::uint32_t device_id = 0;
	std::string device_name;
	std::string remote_path; // leading backslash, e.g. "\\foo\\bar"
};

class PathMapper
{
  public:
	explicit PathMapper(std::string mount_root);

	void UpdateDrives(const std::vector<DriveInfo>& drives);
	std::optional<RemotePath> MapPath(const std::string& absolute_path) const;
	bool IsRoot(const std::string& absolute_path) const;
	std::vector<DriveInfo> Drives() const;

  private:
	std::string Normalize(const std::string& path) const;
	bool IsValidSegment(const std::string& segment) const;

	std::string mount_root_;
	std::vector<DriveInfo> drives_;
};

} // namespace tsclient
