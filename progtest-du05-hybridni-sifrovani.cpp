#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */


bool seal(string_view inFile, string_view outFile, string_view publicKeyFile, string_view symmetricCipher)
{
    if((inFile.data() == nullptr)||(outFile.data() == nullptr)||(publicKeyFile.data() == nullptr)||(symmetricCipher.data() == nullptr))
    {
        return false;
    }


    FILE* in = fopen(inFile.data(), "rb");
    if (!in) {
        remove(outFile.data());
        return false;

    }

    FILE* out = fopen(outFile.data(), "wb");
    if (!out) {
        fclose(in);
        remove(outFile.data());
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(in);
        fclose(out);
        remove(outFile.data());
        return false;
    }

    FILE* pubFile = fopen(publicKeyFile.data(), "rb");
    if (!pubFile) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        remove(outFile.data());
        return false;
    }

    EVP_PKEY* pubKey = NULL;
    pubKey = PEM_read_PUBKEY(pubFile, NULL, NULL, NULL);
    fclose(pubFile);

    if (!pubKey) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        remove(outFile.data());
        return false;
    }

    const EVP_CIPHER* cipher = EVP_get_cipherbyname(symmetricCipher.data());
    if (!cipher) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }

    int keySize = EVP_PKEY_size(pubKey);
    int ivSize = EVP_CIPHER_iv_length(cipher);

    std::unique_ptr<unsigned char[]> sharedKey(new unsigned char[keySize]);
    std::unique_ptr<unsigned char[]> iv(new unsigned char[ivSize]);
    int sharedKeyLen, ivLen;

    unsigned char* temp = &sharedKey[0];

    if (EVP_SealInit(ctx, cipher, &temp, &sharedKeyLen, iv.get(), &pubKey, 1) != 1) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }

    int cipherNID = EVP_CIPHER_CTX_nid(ctx);
    size_t check;
    check = fwrite(&cipherNID, sizeof(int), 1, out);
    if(check != 1){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }

    check = fwrite(&sharedKeyLen, sizeof(int), 1, out);
    if(check != 1){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }
    check = fwrite(sharedKey.get(), 1, sharedKeyLen, out);
    if(int(check) != sharedKeyLen){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }

    ivLen = EVP_CIPHER_iv_length(cipher);
    check = fwrite(iv.get(), 1, ivLen, out);
    if(int(check) != ivLen){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }

    unsigned char in_buffer[1024];
    unsigned char out_buffer[1024 * 2];
    int len, cipherLen;
    while ((len = fread(in_buffer, 1, sizeof(in_buffer), in)) > 0) {
        if (EVP_SealUpdate(ctx, out_buffer, &cipherLen, in_buffer, len) != 1) {
            fclose(in);
            fclose(out);
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(pubKey);
            remove(outFile.data());
            return false;
        }
        check = fwrite(out_buffer, 1, cipherLen, out);
        if(int(check) != cipherLen){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }
    }

    if (EVP_SealFinal(ctx, out_buffer, &cipherLen) != 1) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }
    check = fwrite(out_buffer, 1, cipherLen, out);
    if(int(check) != cipherLen){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        remove(outFile.data());
        return false;
    }

    fclose(in);
    fclose(out);
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pubKey);
    return true;
}


bool open(string_view inFile, string_view outFile, string_view privateKeyFile)
{
    
    if((inFile.data() == nullptr)||(outFile.data() == nullptr)||(privateKeyFile.data() == nullptr))
    {
        return false;
    }
    
    FILE* in = fopen(inFile.data(), "rb");
    if (!in) {
        remove(outFile.data());
        return false;
    }

    FILE* out = fopen(outFile.data(), "wb");
    if (!out) {
        fclose(in);
        remove(outFile.data());
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(in);
        fclose(out);
        remove(outFile.data());
        return false;
    }

    EVP_PKEY* privKey = NULL;
    FILE* privFile = fopen(privateKeyFile.data(), "rb");
    if (!privFile) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        remove(outFile.data());
        return false;
    }

    privKey = PEM_read_PrivateKey(privFile, NULL, NULL, NULL);
    fclose(privFile);

    if (!privKey) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        remove(outFile.data());
        return false;
    }


    int cipherNID;
    size_t check;
    check = fread(&cipherNID, sizeof(int), 1, in);
    if(check != 1){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        remove(outFile.data());
        return false;
    }

    int sharedKeyLen;
    check = fread(&sharedKeyLen, sizeof(int), 1, in);
    if(check != 1){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        remove(outFile.data());
        return false;
    }
    unique_ptr<unsigned char[]> encryptedKey(new unsigned char[sharedKeyLen]);
    check = fread(encryptedKey.get(), 1, sharedKeyLen, in);
    if(int(check) != sharedKeyLen){
        fclose(in);
        fclose(out);
        EVP_PKEY_free(privKey);
        EVP_CIPHER_CTX_free(ctx);
        remove(outFile.data());
        return false;
    }
    
    int ivLen = EVP_CIPHER_iv_length(EVP_get_cipherbynid(cipherNID));
    if(ivLen == -1){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        remove(outFile.data());
        return false;
    }
    unique_ptr<unsigned char[]> iv(new unsigned char[ivLen]);
    check = fread(iv.get(), 1, ivLen, in);
    if(int(check) != ivLen){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        remove(outFile.data());
        return false;
    }

    if (EVP_OpenInit(ctx, EVP_get_cipherbynid(cipherNID), encryptedKey.get(), sharedKeyLen, iv.get(), privKey) != 1) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        remove(outFile.data());
        return false;
    }

    unsigned char in_buffer[1024];
    unsigned char out_buffer[1024 * 2];
    int len, plainLen;

    while ((len = fread(in_buffer, 1, sizeof(in_buffer), in)) > 0) {
        if (EVP_OpenUpdate(ctx, out_buffer, &plainLen, in_buffer, len) != 1) {
            fclose(in);
            fclose(out);
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(privKey);
            remove(outFile.data());
            return false;
        }
        check = fwrite(out_buffer, 1, plainLen, out);
        if(int(check) != plainLen){
            fclose(in);
            fclose(out);
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(privKey);
            remove(outFile.data());
            return false;
        }
    }

    if (EVP_OpenFinal(ctx, out_buffer, &plainLen) != 1) {
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        remove(outFile.data());
        return false;
    }
    check = fwrite(out_buffer, 1, plainLen, out);
    if(int(check) != plainLen){
        fclose(in);
        fclose(out);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        remove(outFile.data());
        return false;
    }
    fclose(in);
    fclose(out);
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(privKey);

    return true;
}



#ifndef __PROGTEST__

int main ( void )
{
    assert( seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );
    assert( open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem") );

    assert( open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem") );

    return 0;
}

#endif /* __PROGTEST__ */

