#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>

namespace tsclient
{

template <typename T>
class TtlCache
{
  public:
	using Clock = std::chrono::steady_clock;

	explicit TtlCache(std::chrono::milliseconds ttl) : ttl_(ttl) {}

	void Put(const std::string& key, T value)
	{
		const auto now = Clock::now();
		entries_[key] = Entry{ now + ttl_, std::move(value) };
	}

	std::optional<T> Get(const std::string& key)
	{
		const auto now = Clock::now();
		auto it = entries_.find(key);
		if (it == entries_.end())
			return std::nullopt;
		if (it->second.expires_at <= now)
		{
			entries_.erase(it);
			return std::nullopt;
		}
		return it->second.value;
	}

	void Erase(const std::string& key) { entries_.erase(key); }

	void Clear() { entries_.clear(); }

  private:
	struct Entry
	{
		Clock::time_point expires_at;
		T value;
	};

	std::unordered_map<std::string, Entry> entries_;
	std::chrono::milliseconds ttl_;
};

} // namespace tsclient
