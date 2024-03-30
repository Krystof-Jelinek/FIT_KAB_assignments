//Kryštof Jelínek -- jelinkry
#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif /* _PROGTEST_ */

//Kryštof Jelínek -- jelinkry

bool encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
	// Ensure that required parameters are set
    if (!config.m_crypto_function || !config.m_key || !config.m_key_len) {
        return false;
    }

    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;

    // Initialize OpenSSL library
    OpenSSL_add_all_algorithms();

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    // Get the cipher
    cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, config.m_key.get(), config.m_IV.get()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Open input file
    std::ifstream inFile(in_filename, std::ios::binary);
    if (!inFile.is_open()) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Open output file
    std::ofstream outFile(out_filename, std::ios::binary);
    if (!outFile.is_open()) {
        inFile.close();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    //read the headers
    char headerBuf[18];
    inFile.read(headerBuf, sizeof(headerBuf));
    outFile.write(headerBuf, sizeof(headerBuf));

    // Encryption buffer
    const size_t BLOCK_SIZE = 16; // AES block size
    uint8_t inBuf[BLOCK_SIZE];
    uint8_t outBuf[BLOCK_SIZE + BLOCK_SIZE]; //for possible padding

    int outLen;
    while (!inFile.eof()) {
        inFile.read(reinterpret_cast<char *>(inBuf), BLOCK_SIZE);
        size_t bytesRead = inFile.gcount();

        // Encrypt the data
        if (EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1) {
            inFile.close();
            outFile.close();
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outFile.write(reinterpret_cast<const char *>(outBuf), outLen);
    }

    // Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        inFile.close();
        outFile.close();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write(reinterpret_cast<const char *>(outBuf), outLen);

    // Clean up
    inFile.close();
    outFile.close();
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
    // Ensure that required parameters are set
    if (!config.m_crypto_function || !config.m_key || !config.m_key_len) {
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    // Initialize the decryption operation
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, config.m_key.get(), config.m_IV.get()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Open input file
    std::ifstream inFile(in_filename, std::ios::binary);
    if (!inFile.is_open()) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Open output file
    std::ofstream outFile(out_filename, std::ios::binary);
    if (!outFile.is_open()) {
        inFile.close();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Copy the first 18 bytes (headers) without decryption
    char headerBuf[18];
    inFile.read(headerBuf, sizeof(headerBuf));
    outFile.write(headerBuf, sizeof(headerBuf));

    // Decryption buffer
    const size_t BLOCK_SIZE = 16; // AES block size
    uint8_t inBuf[BLOCK_SIZE];
    uint8_t outBuf[BLOCK_SIZE + BLOCK_SIZE];

    int outLen;
    while (!inFile.eof()) {
        inFile.read(reinterpret_cast<char *>(inBuf), BLOCK_SIZE);
        size_t bytesRead = inFile.gcount();

        // Decrypt the data
        if (EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1) {
            inFile.close();
            outFile.close();
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outFile.write(reinterpret_cast<const char *>(outBuf), outLen);
    }

    // Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        inFile.close();
        outFile.close();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write(reinterpret_cast<const char *>(outBuf), outLen);

    // Clean up
    inFile.close();
    outFile.close();
    EVP_CIPHER_CTX_free(ctx);
    return true;
}


#ifndef __PROGTEST__

bool compare_files ( const char * name1, const char * name2 )
{
    // Open the first file
    std::ifstream file1(name1, std::ios::binary);
    if (!file1.is_open()) {
        return false;
    }

    // Open the second file
    std::ifstream file2(name2, std::ios::binary);
    if (!file2.is_open()) {
        file1.close();
        return false;
    }

    // Compare file sizes
    file1.seekg(0, std::ios::end);
    file2.seekg(0, std::ios::end);
    if (file1.tellg() != file2.tellg()) {
        file1.close();
        file2.close();
        return false;
    }

    // Reset file pointers to the beginning
    file1.seekg(0, std::ios::beg);
    file2.seekg(0, std::ios::beg);

    // Compare file contents
    constexpr size_t BUFFER_SIZE = 1024;
    uint8_t buffer1[BUFFER_SIZE];
    uint8_t buffer2[BUFFER_SIZE];
    size_t bytesRead1, bytesRead2;

    do {
        file1.read(reinterpret_cast<char *>(buffer1), BUFFER_SIZE);
        bytesRead1 = file1.gcount();

        file2.read(reinterpret_cast<char *>(buffer2), BUFFER_SIZE);
        bytesRead2 = file2.gcount();

        if (bytesRead1 != bytesRead2 || memcmp(buffer1, buffer2, bytesRead1) != 0) {
            file1.close();
            file2.close();
            cout << "fuck" << endl;
            return false;
        }
    } while (bytesRead1 > 0);

    // Close files and return true if contents are identical
    file1.close();
    file2.close();
    return true;
}

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
    
}

#endif /* _PROGTEST_ */
