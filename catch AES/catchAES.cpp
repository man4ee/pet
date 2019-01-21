#include <iostream>
#include <cstdlib>
#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include <openssl/evp.h>
using namespace std;
typedef unsigned char data_128[16];
    
data_128 key = 
{		
    0x00, 0x00, 0x00, 0x00, 		
    0x00, 0x00, 0x00, 0x00, 		
    0x00, 0x00, 0x00, 0x00, 		
    0x00, 0x00, 0x00, 0x00 	
}; 

data_128 iv = 
{		
    0x00, 0x00, 0x00, 0x00, 		
    0x00, 0x00, 0x00, 0x00, 		
    0x00, 0x00, 0x00, 0x00, 		
    0x00, 0x00, 0x00, 0x00 	
}; 

data_128  plainText = 
{ 		
    0xf3, 0x44, 0x81, 0xec, 		
    0x3c, 0xc6, 0x27, 0xba, 		
    0xcd, 0x5d, 0xc3, 0xfb, 		
    0x08, 0xf2, 0x73, 0xe6 	
}; 

data_128  cryptedText = 
{		
    0x03, 0x36, 0x76, 0x3e, 		
    0x96, 0x6d, 0x92, 0x59, 		
    0x5a, 0x56, 0x7c, 0xc9, 		
    0xce, 0x53, 0x7f, 0x5e 	
}; 
    
int out_Len;
data_128 out;
EVP_CIPHER_CTX* ctx; 	

//EVP_CIPHER_CTX* AES_128_ECB_Testing::ctx = nullptr;

TEST_CASE( "Test_Encrypt_NoPading", "" ) {
    ctx = EVP_CIPHER_CTX_new();
    REQUIRE(ctx != nullptr);
    REQUIRE(EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv) == 1);
    REQUIRE(EVP_CIPHER_CTX_set_padding(ctx, 0) == 1);
    REQUIRE(EVP_EncryptUpdate(ctx, out, &out_Len, plainText, sizeof(plainText)) == 1);
    REQUIRE(out_Len == 16);
    REQUIRE(EVP_EncryptFinal(ctx,out,  &out_Len) == 1);
    REQUIRE(out_Len == 0);
    REQUIRE(memcmp(out,cryptedText, 16) == 0);
    EVP_CIPHER_CTX_free(ctx);
}

TEST_CASE( "Test_Decrypt_NoPading", "" ) {
    ctx = EVP_CIPHER_CTX_new();
    REQUIRE(ctx != nullptr);
    REQUIRE(EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv) == 1);
    REQUIRE(EVP_CIPHER_CTX_set_padding(ctx, 0) == 1);
    REQUIRE(EVP_DecryptUpdate(ctx, out, &out_Len, cryptedText, sizeof(cryptedText)) == 1);
    REQUIRE (out_Len == 16);
    REQUIRE(EVP_DecryptFinal(ctx, out,  &out_Len) == 1);
    REQUIRE(out_Len == 0);
    REQUIRE(memcmp(out, plainText, 16) == 0);
    EVP_CIPHER_CTX_free(ctx);
}

TEST_CASE( "Test_Encrypt_NoPading_sNotMultiple", "" ) {
    ctx = EVP_CIPHER_CTX_new();
    REQUIRE(ctx != nullptr);
    REQUIRE(EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv) == 1);
    REQUIRE(EVP_CIPHER_CTX_set_padding(ctx, 0) == 1);
    REQUIRE(EVP_EncryptUpdate(ctx, out, &out_Len, plainText, sizeof(plainText)/2) == 1);
    REQUIRE (out_Len == 0);
    REQUIRE(EVP_EncryptFinal(ctx, out, &out_Len) == 0);
    REQUIRE(out_Len == 0);
    EVP_CIPHER_CTX_free(ctx);
}

TEST_CASE( "Test_Encrypt_Pading_sMultiple", "" ) {
    ctx = EVP_CIPHER_CTX_new();
    REQUIRE(ctx != nullptr);
    REQUIRE(EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key,  iv) == 1);
    REQUIRE(EVP_CIPHER_CTX_set_padding(ctx, 1) == 1);
    REQUIRE(EVP_EncryptUpdate(ctx, out, &out_Len, plainText, sizeof(plainText)/2) == 1);
    REQUIRE(out_Len == 0);
    REQUIRE(EVP_EncryptFinal(ctx, out, &out_Len) == 1);
    REQUIRE(out_Len == 16);
    REQUIRE(EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv) == 1);
    REQUIRE(EVP_CIPHER_CTX_set_padding(ctx, 1) == 1);
    REQUIRE(EVP_DecryptUpdate(ctx, out, &out_Len, out, sizeof(out)) == 1);
    REQUIRE(out_Len == 0);
    REQUIRE(EVP_DecryptFinal(ctx, out, &out_Len) == 1);
    REQUIRE(out_Len == 8);
    for(int i = 0;i < 8;i++)
    {
        REQUIRE(out[8+i] == 8);
    }
    EVP_CIPHER_CTX_free(ctx);
}
