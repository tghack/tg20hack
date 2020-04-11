#include <array>
#include <random>
#include <string>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>

static std::string read_all(const std::string& filename)
{
	std::ifstream in{filename, std::ios::binary | std::ios::ate};
    if (in.fail()) {
        return "";
    }

	auto size = in.tellg();
	std::string str(size, '\0');

	in.seekg(0);
	in.read(&str[0], size);

	return str;
}

// - /etc/lsb-release
static std::string get_lsb_release(void)
{
	return read_all("/etc/lsb-release");
}

// - /etc/debian_version
static std::string get_debian_version(void)
{
	return read_all("/etc/debian_version");
}

// - /etc/legal
static std::string get_legal(void)
{
	return read_all("/etc/legal");
}

// - /etc/issue
static std::string get_issue(void)
{
	return read_all("/etc/issue");
}

// - /etc/os-release
static std::string get_os_release(void)
{
	return read_all("/etc/os-release");
}

// - /etc/hostname
static std::string get_hostname(void)
{
	return read_all("/etc/hostname");
}

// - self/PID
static std::string get_pid(void)
{
	pid_t pid = getpid();
	return std::to_string(pid);
}

std::array<uint8_t, 16> extern_gen_key(void)
{
	std::array<uint8_t, 16> key{};

	std::string all_host_specific = get_hostname() +
					get_legal() +
					get_debian_version() +
					get_lsb_release() +
					get_issue() +
					get_os_release();

	// Hash data
	std::size_t fst_part = std::hash<std::string>{}(all_host_specific);
	std::size_t snd_part = std::hash<std::string>{}(get_pid());

	// Copy hashes into key array
	std::memcpy(&key[0], &fst_part, 8);
	std::memcpy(&key[4], &snd_part, 8);

	return key;
}
