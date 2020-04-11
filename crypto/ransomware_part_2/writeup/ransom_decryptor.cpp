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

#include "key_gen.hpp"

namespace fs = std::filesystem;


bool decrypt_file(const std::string& file_path, const CryptoPP::SecByteBlock& key, pid_t pid)
{
    // Read generated IV from file
    CryptoPP::byte iv[CryptoPP::RC6::BLOCKSIZE];
    auto arr_sink = new CryptoPP::ArraySink(iv, sizeof(iv));
    auto source = new CryptoPP::FileSource(file_path.c_str(), false, arr_sink, true);
    source->Pump(CryptoPP::RC6::BLOCKSIZE);

	// Set up crypto object
	CryptoPP::CBC_Mode<CryptoPP::RC6>::Decryption crypt(key, key.size(), iv);

    // Read from file, decrypt and write to file
    std::string contents;
    source->Detach(new CryptoPP::StreamTransformationFilter(crypt,
                new CryptoPP::StringSink(contents)));
    try {
        source->PumpAll();
    }
    catch (CryptoPP::InvalidCiphertext const&) {
        delete source;
        return false;
    }
    delete source;

    // Return true if we find TG20 in a decrypted file
    if (contents.find("TG20") != std::string::npos) {
        std::cout << std::endl << std::endl <<
            "PID: " << pid << " Contents: " << contents << std::endl;
        return true;
    }

    return false;
}

int main(const int argc, const char *argv[])
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <system-file-directory>" << std::endl;
        return -1;
    }

    for (pid_t i = 0; i < INT_MAX; i++) {
        const auto real_key = extern_gen_key(std::string(argv[1]), i);
        const auto key = CryptoPP::SecByteBlock(real_key.data(), real_key.size());

        // Iterate over regular files and decrypt them
        for (auto &entry : fs::recursive_directory_iterator(fs::current_path())) {
                if (entry.is_regular_file()) {
                    // Exit if we successfully decrypted a file containing TG20
                    if (decrypt_file(entry.path().string(), key, i) == true) {
                        return 0;
                    }
                }
        }
        fprintf(stderr, "\rTesting PID: [%06i]", i);
    }

	return 0;
}
