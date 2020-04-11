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
        std::cerr << "This is not UBUNTU!" << std::endl;
        return "";
    }

	auto size = in.tellg();
	std::string str(size, '\0');

	in.seekg(0);
	in.read(&str[0], size);

	return str;
}

// - /etc/lsb-release
static std::string get_lsb_release(const std::string& path)
{
	return read_all(path+"/lsb-release");
}

// - /etc/debian_version
static std::string get_debian_version(const std::string& path)
{
	return read_all(path+"/debian_version");
}

// - /etc/legal
static std::string get_legal(const std::string& path)
{
	return read_all(path+"/legal");
}

// - /etc/issue
static std::string get_issue(const std::string& path)
{
	return read_all(path+"/issue");
}

// - /etc/os-release
static std::string get_os_release(const std::string& path)
{
	return read_all(path+"/os-release");
}

// - /etc/hostname
static std::string get_hostname(const std::string& path)
{
	return read_all(path+"/hostname");
}

// - self/PID
static std::string get_pid(void)
{
	pid_t pid = getpid();
	return std::to_string(pid);
}

std::array<uint8_t, 16> extern_gen_key(const std::string& path, const pid_t pid)
{
	std::array<uint8_t, 16> key{};

	std::string all_host_specific = get_hostname(path) +
					get_legal(path) +
					get_debian_version(path) +
					get_lsb_release(path) +
					get_issue(path) +
					get_os_release(path);

	// Hash data
	std::size_t fst_part = std::hash<std::string>{}(all_host_specific);
	std::size_t snd_part = std::hash<std::string>{}(std::to_string(pid));

	// Copy hashes into key array
	std::memcpy(&key[0], &fst_part, 8);
	std::memcpy(&key[4], &snd_part, 8);

	return key;
}
