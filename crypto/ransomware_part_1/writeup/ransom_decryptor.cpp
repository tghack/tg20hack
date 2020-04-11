#include <array>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <cryptopp/hex.h>
#include <cryptopp/rc6.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>

namespace fs = std::filesystem;


CryptoPP::SecByteBlock decode_key(const std::string& encoded_key)
{
    CryptoPP::byte key[16] = { 0 };
    CryptoPP::StringSource(encoded_key, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::ArraySink(key, sizeof(key))));
	return CryptoPP::SecByteBlock(key, sizeof(key));
}

void decrypt_file(const std::string& file_path, const CryptoPP::SecByteBlock& key)
{
    // Read generated IV from file
    CryptoPP::byte iv[CryptoPP::RC6::BLOCKSIZE];
    auto source = new CryptoPP::FileSource(file_path.c_str(), false, new CryptoPP::ArraySink(iv, sizeof(iv)), true);
    source->Pump(CryptoPP::RC6::BLOCKSIZE);

	// Set up crypto object
	CryptoPP::CBC_Mode<CryptoPP::RC6>::Decryption crypt(key, key.size(), iv);

    // Read from file, decrypt and write to file
    source->Detach(new CryptoPP::StreamTransformationFilter(crypt, new CryptoPP::FileSink((file_path + ".dec").c_str(), true)));
    source->PumpAll();
    delete source;

	remove(file_path.c_str());
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <hex-encoded-key>" << std::endl;
        return -1;
    }
	/// Generate key
	auto key = decode_key(std::string(argv[1]));

	// Iterate over regular files and encrypt them
	for (auto &entry : fs::recursive_directory_iterator(fs::current_path())) {
		if (entry.is_regular_file()) {
			decrypt_file(entry.path().string(), key);
		}
	}

	return 0;
}
