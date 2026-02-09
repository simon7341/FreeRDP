#include "path_mapper.h"

#include <algorithm>
#include <sstream>

namespace tsclient
{

PathMapper::PathMapper(std::string mount_root) : mount_root_(std::move(mount_root))
{
	if (!mount_root_.empty() && mount_root_.back() == '/')
		mount_root_.pop_back();
}

void PathMapper::UpdateDrives(const std::vector<DriveInfo>& drives)
{
	drives_ = drives;
}

std::vector<DriveInfo> PathMapper::Drives() const
{
	return drives_;
}

bool PathMapper::IsRoot(const std::string& absolute_path) const
{
	return Normalize(absolute_path) == mount_root_;
}

std::optional<RemotePath> PathMapper::MapPath(const std::string& absolute_path) const
{
	const std::string normalized = Normalize(absolute_path);
	if (normalized.rfind(mount_root_, 0) != 0)
		return std::nullopt;

	std::string relative = normalized.substr(mount_root_.size());
	if (relative.empty())
		return std::nullopt;
	if (relative.front() == '/')
		relative.erase(relative.begin());

	std::stringstream ss(relative);
	std::string segment;
	std::vector<std::string> parts;
	while (std::getline(ss, segment, '/'))
	{
		if (segment.empty())
			continue;
		if (!IsValidSegment(segment))
			return std::nullopt;
		parts.push_back(segment);
	}

	if (parts.empty())
		return std::nullopt;

	const std::string drive_name = parts.front();
	auto it = std::find_if(drives_.begin(), drives_.end(), [&](const DriveInfo& drive) {
		return drive.dos_name == drive_name;
	});
	if (it == drives_.end())
		return std::nullopt;

	std::string remote_path = "\\";
	for (size_t i = 1; i < parts.size(); ++i)
	{
		remote_path.append(parts[i]);
		if (i + 1 < parts.size())
			remote_path.append("\\");
	}

	return RemotePath{ it->device_id, it->dos_name, remote_path };
}

std::string PathMapper::Normalize(const std::string& path) const
{
	std::string normalized = path;
	std::replace(normalized.begin(), normalized.end(), '\\', '/');

	// Remove trailing slash except root.
	if (normalized.size() > 1 && normalized.back() == '/')
		normalized.pop_back();
	return normalized;
}

bool PathMapper::IsValidSegment(const std::string& segment) const
{
	if (segment == "." || segment == "..")
		return false;
	return segment.find('/') == std::string::npos && segment.find('\\') == std::string::npos;
}

} // namespace tsclient
