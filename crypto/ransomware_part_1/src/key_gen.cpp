#include <array>
#include <random>
#include <cstdint>

std::array<uint8_t, 16> extern_gen_key(void)
{
	std::random_device rd;
	std::array<uint8_t, 16> key;
	for (size_t i = 0; i < key.size(); i++) {
		key[i] = rd();
	}

	return key;
}
