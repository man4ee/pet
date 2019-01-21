#include <iostream>
#include <cstdlib>
#include <gtest/gtest.h>
#include <openssl/evp.h>

using namespace std;


typedef unsigned char data_256[32];

class SHA256_Test : public ::testing::Test 
{
protected:
	
	string data1 = "abc";
	string data2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	string data3;
	data_256 Hash1 = 
	{
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
	data_256 Hash2 = 
	{
		0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
		0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
		0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
		0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
	};
	data_256 Hash3= 
	{
		0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
		0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
		0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
		0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
	};
	unsigned int hashedSize = 0;

	static EVP_MD_CTX* sha256;

	virtual void SetUp()    
	{ 
		sha256 = EVP_MD_CTX_create(); 
	}
	virtual void TearDown() 
	{ 
		EVP_MD_CTX_destroy(sha256);  
	}

};



EVP_MD_CTX* SHA256_Test::sha256 = nullptr;

TEST_F(SHA256_Test, Test_data1)
{
    ASSERT_TRUE(EVP_DigestInit(sha256 , EVP_sha256()));
    ASSERT_TRUE(EVP_DigestUpdate(sha256, data1.c_str() ,data1.length()));
	unsigned int hashSize = EVP_MD_size(EVP_sha256());
	unsigned char* result = new unsigned char[hashSize];
	ASSERT_TRUE(EVP_DigestFinal_ex(sha256, result, &hashSize));
	ASSERT_EQ(memcmp(result, Hash1, 32), 0);
}

TEST_F(SHA256_Test, Test_data2)
{
    ASSERT_TRUE(EVP_DigestInit(sha256 , EVP_sha256()));
    ASSERT_TRUE(EVP_DigestUpdate(sha256, data2.c_str() ,data2.length()));
	unsigned int hashSize = EVP_MD_size(EVP_sha256());
	unsigned char* result = new unsigned char[hashSize];
	ASSERT_TRUE(EVP_DigestFinal_ex(sha256, result, &hashSize));
	ASSERT_EQ(memcmp(result, Hash2, 32), 0);
}

TEST_F(SHA256_Test, Test_data3)
{
	for(int i = 0;i<1000000;i++)
	{
		data3+="a";
	}
    ASSERT_TRUE(EVP_DigestInit(sha256 , EVP_sha256()));
    ASSERT_TRUE(EVP_DigestUpdate(sha256, data3.c_str() ,data3.length()));
	unsigned int hashSize = EVP_MD_size(EVP_sha256());
	unsigned char* result = new unsigned char[hashSize];
	ASSERT_TRUE(EVP_DigestFinal_ex(sha256, result, &hashSize));
	ASSERT_EQ(memcmp(result, Hash3, 32), 0);
}



int main(int argc, char *argv[]){
    ::testing::InitGoogleTest(&argc, const_cast<char**>(argv));
	
    return RUN_ALL_TESTS();
}
