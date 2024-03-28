#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

#endif /* __PROGTEST__ */

unsigned char hexCharToByte(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    // Handle invalid characters
    throw std::invalid_argument("Invalid hexadecimal character");
}

unsigned char twoCharsToByte(char first, char second){
    unsigned char res = hexCharToByte(first);
    res = (res << 4) | hexCharToByte(second);
    return res;
}

std::string bytesToHexString(const unsigned char* bytes, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return ss.str();
}

std::string generateRandomString(size_t length) {
    std::string randomString;
    randomString.resize(length);

    // Generate random bytes
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&randomString[0]), length) != 1) {
        // Error handling if RAND_bytes fails
        throw std::runtime_error("Failed to generate random bytes");
    }

    // Convert bytes to printable characters
    for (char& c : randomString) {
        // Map the random byte to the printable ASCII range
        c = static_cast<char>((c % ('~' - ' ')) + ' ');
    }

    return randomString;
}

int countLeadingZeros(const string & hash) {
    int lenght = 128; 
    if((lenght % 2) != 0){
        throw std::invalid_argument("hash must have even number of chars");
    }
    int count = 0;
    for (int i = 0; i < lenght; i += 2) {
        unsigned char byte = twoCharsToByte(hash[i], hash[i+1]);
        if((byte & 0xFF) == 0){
            count += 8; // Add 8 leading zeros if the byte is zero
            continue;
        } 
        // Count additional leading zeros in the byte
        while ((byte & 0x80) == 0) {
            count++;
            byte <<= 1;
        }
        break;
    }
    return count;
}

int countLeadingZeros(const unsigned char (&hash)[64]) {
    int lenght = 64; 
    int count = 0;
    unsigned char byte;
    for (int i = 0; i < lenght; i ++) {
        if((hash[i] & 0xFF) == 0){
            count += 8; // Add 8 leading zeros if the byte is zero
            continue;
        }
        byte = hash[i];
        // Count additional leading zeros in the byte
        while ((byte & 0x80) == 0) {
            count++;
            byte <<= 1;
        }
        break;
    }
    return count;
}

int countLeadingZeros(unsigned char * hash, unsigned int length) {
    int count = 0;
    unsigned char byte;
    for (unsigned int i = 0; i < length; i ++) {
        if((hash[i] & 0xFF) == 0){
            count += 8; // Add 8 leading zeros if the byte is zero
            continue;
        }
        byte = hash[i];
        // Count additional leading zeros in the byte
        while ((byte & 0x80) == 0) {
            count++;
            byte <<= 1;
        }
        break;
    }
    return count;
}


int findHash (int numberZeroBits, string & outputMessage, string & outputHash) {
    if (numberZeroBits < 0) return 0;
    if (numberZeroBits > 512) return 0;

    const int HASH_SIZE = 64; // SHA-512 produces 64-byte hash
    unsigned char * hash = new unsigned char[HASH_SIZE];
    char hashFunction[] = "sha512";
    unsigned int length = 64;

    EVP_MD_CTX * ctx; //kontext
    const EVP_MD * type; //typ hash funkce

    /* Inicializace OpenSSL hash funkci */
    OpenSSL_add_all_digests();
    /* Zjisteni, jaka hashovaci funkce ma byt pouzita */
    type = EVP_get_digestbyname(hashFunction);
    if (!type) {
        delete[] hash;
        return 0;
    }

    ctx = EVP_MD_CTX_new(); // create context for hashing
    if (ctx == NULL){
        delete[] hash;
        return 0;
    }

    unsigned char * randomBytes = new unsigned char[64];
    void* ptr;
    
    // Generate random bytes
    if (RAND_bytes(randomBytes, length) != 1) {
        // Error handling if RAND_bytes fails
        delete[] hash;
        delete[] randomBytes;
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to generate random bytes");
    }

    while(true){

    ptr = randomBytes;

    /* Hash the text */
    if (!EVP_DigestInit_ex(ctx, type, NULL)){
        delete[] hash;
        delete[] randomBytes;
        EVP_MD_CTX_free(ctx);
        return 0;
    } 

    if (!EVP_DigestUpdate(ctx, ptr, length)){
        delete[] hash;
        delete[] randomBytes;
        EVP_MD_CTX_free(ctx);
        return 0;
    }    

    if (!EVP_DigestFinal_ex(ctx, hash, &length)){
        delete[] hash;
        delete[] randomBytes;
        EVP_MD_CTX_free(ctx);
        return 0;
    }


    if(countLeadingZeros(hash,length) >= numberZeroBits){
        unsigned char* uchar_ptr = reinterpret_cast<unsigned char*>(ptr);
        outputMessage = (bytesToHexString(uchar_ptr,length));
        outputHash = bytesToHexString(hash,length);
        //cout << "Hash textu " << outputMessage << " je" << endl;
        //cout << outputHash << endl;
        delete[] hash;
        delete[] randomBytes;
        EVP_MD_CTX_free(ctx); // destroy the context
        return 1;
    }
    swap(randomBytes,hash);
    }
    delete[] hash;
    delete[] randomBytes;
    EVP_MD_CTX_free(ctx);
    return 0;
}

int findHashEx (int numberZeroBits, string & outputMessage, string & outputHash, string_view hashType) {
    if (numberZeroBits < 0) return 0;
    OpenSSL_add_all_digests();
    const EVP_MD * type; //typ hash funkce
    const char* hashTypeCharPtr = hashType.data();

    type = EVP_get_digestbyname(hashTypeCharPtr);
    if (!type) {
        return 0;
    }

    int allbyts = EVP_MD_size(type);
    if(numberZeroBits > (allbyts*8)) return 0;

    const int HASH_SIZE = allbyts; // SHA-512 produces 64-byte hash
    unsigned char * hash = new unsigned char [HASH_SIZE];
    unsigned int length = HASH_SIZE;

    EVP_MD_CTX * ctx; //kontext

    /* Inicializace OpenSSL hash funkci */
    /* Zjisteni, jaka hashovaci funkce ma byt pouzita */

    ctx = EVP_MD_CTX_new(); // create context for hashing
    if (ctx == NULL){
        delete[] hash;
        return 0;
    }

    unsigned char* randomBytes;
    void* ptr;

    while(true){

    randomBytes = new unsigned char[length];

    // Generate random bytes
    if (RAND_bytes(randomBytes, length) != 1) {
        // Error handling if RAND_bytes fails
        delete[] hash;
        delete[] randomBytes; // Clean up allocated memory
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to generate random bytes");
    }

    ptr = randomBytes;

    /* Hash the text */
    if (!EVP_DigestInit_ex(ctx, type, NULL)){
        delete[] hash;
        delete[] randomBytes; 
        EVP_MD_CTX_free(ctx);
        return 0;
    } 

    if (!EVP_DigestUpdate(ctx, ptr, length)){
        delete[] hash;
        delete[] randomBytes; 
        EVP_MD_CTX_free(ctx);
        return 0;
    }    

    if (!EVP_DigestFinal_ex(ctx, hash, &length)){
        delete[] hash;
        delete[] randomBytes; 
        EVP_MD_CTX_free(ctx);
        return 0;
    }


    if(countLeadingZeros(hash,length) >= numberZeroBits){
        unsigned char* uchar_ptr = reinterpret_cast<unsigned char*>(ptr);
        outputMessage = (bytesToHexString(uchar_ptr,length));
        outputHash = bytesToHexString(hash,length);
        //cout << "Hash textu " << outputMessage << " je" << endl;
        //cout << outputHash << endl;
        EVP_MD_CTX_free(ctx); // destroy the context
        delete[] randomBytes;
        delete[] hash;
        return 1;
    }
    delete[] randomBytes;
    }
    delete[] hash;
    delete[] randomBytes;
    EVP_MD_CTX_free(ctx);
    return 0;
}

void printBits(unsigned char c) {
    // Start from the most significant bit (bit 7) to the least significant bit (bit 0)
    for (int i = 7; i >= 0; --i) {
        // Extract the i-th bit from the byte using bitwise AND
        unsigned char bit = (c >> i) & 0x01;
        // Print the bit
        std::cout << static_cast<int>(bit);
    }
    cout << endl;
}

#ifndef __PROGTEST__

int checkHash(int bits, const string & hash) {
    if(countLeadingZeros(hash) >= bits){
        return 1;
    }
    return 0;
}

int main (void) {
    string hash, message;
    findHash(20,message,hash);

    
    assert(findHashEx(512,message,hash,"sha256") == 0);

    
    assert(findHashEx(0, message, hash,"sha512") == 1);
    assert(!message.empty() && !hash.empty() && checkHash(0, hash));
    message.clear();
    hash.clear();
    assert(findHashEx(1, message, hash,"sha512") == 1);
    assert(!message.empty() && !hash.empty() && checkHash(1, hash));
    message.clear();
    hash.clear();
    assert(findHashEx(2, message, hash,"sha512") == 1);
    assert(!message.empty() && !hash.empty() && checkHash(2, hash));
    message.clear();
    hash.clear();
    assert(findHashEx(3, message, hash,"sha256") == 1);
    assert(!message.empty() && !hash.empty() && checkHash(3, hash));
    message.clear();
    hash.clear();
    assert(findHashEx(-1, message, hash,"sha256") == 0);
    
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */










