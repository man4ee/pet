#include <iostream>
#include <cstdlib>
#include <gtest/gtest.h>
#include <openssl/evp.h>

using namespace std;


typedef unsigned char data_128[16];

class AES_128_ECB_Testing : public ::testing::Test { 
    
    protected: 	
    
        data_128 key = {		
            0x00, 0x00, 0x00, 0x00, 		
            0x00, 0x00, 0x00, 0x00, 		
            0x00, 0x00, 0x00, 0x00, 		
            0x00, 0x00, 0x00, 0x00 	
        }; 

        data_128 iv = {		
            0x00, 0x00, 0x00, 0x00, 		
            0x00, 0x00, 0x00, 0x00, 		
            0x00, 0x00, 0x00, 0x00, 		
            0x00, 0x00, 0x00, 0x00 	
        }; 	

        data_128  plainText = { 		
            0xf3, 0x44, 0x81, 0xec, 		
            0x3c, 0xc6, 0x27, 0xba, 		
            0xcd, 0x5d, 0xc3, 0xfb, 		
            0x08, 0xf2, 0x73, 0xe6 	
        }; 

        data_128  cryptedText = {		
            0x03, 0x36, 0x76, 0x3e, 		
            0x96, 0x6d, 0x92, 0x59, 		
            0x5a, 0x56, 0x7c, 0xc9, 		
            0xce, 0x53, 0x7f, 0x5e 	
        }; 
    
    int out_Len;
    data_128 out;

    static EVP_CIPHER_CTX* ctx; 	
    
    static void SetUpTestCase() { 
        ctx = EVP_CIPHER_CTX_new();
    } 	
    
    static void TearDownTestCase() { 
        
        EVP_CIPHER_CTX_free(ctx);   
    }

    virtual void SetUp()    {} 	
    virtual void TearDown() {}
};
EVP_CIPHER_CTX* AES_128_ECB_Testing::ctx = nullptr;

TEST_F (AES_128_ECB_Testing, Testing_1_Encrypt){
    ASSERT_EQ(EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv), 1);
    ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx, 0));
    ASSERT_TRUE(EVP_EncryptUpdate(ctx, out, &out_Len, plainText, sizeof(plainText)));
    ASSERT_EQ (out_Len, 16);
    ASSERT_TRUE(EVP_EncryptFinal(ctx, out,  &out_Len));
    ASSERT_EQ(out_Len, 0);
    ASSERT_EQ(memcmp(out, cryptedText, 16), 0);
}
TEST_F (AES_128_ECB_Testing, Testing_2_Decrypt){
    ASSERT_EQ(EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv), 1);
    ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx, 0));
    ASSERT_TRUE(EVP_DecryptUpdate(ctx, out, &out_Len, cryptedText, sizeof(cryptedText)));
    ASSERT_EQ (out_Len, 16);
    ASSERT_EQ(EVP_DecryptFinal(ctx, out,  &out_Len), 1);
    ASSERT_EQ(out_Len, 0);
    ASSERT_EQ(memcmp(out, plainText, 16), 0); 
}
TEST_F (AES_128_ECB_Testing, Testing_3_off_Pading_No_Multiply){
    ASSERT_EQ(EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv), 1);
    ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx, 0));
    ASSERT_TRUE(EVP_EncryptUpdate(ctx, out, &out_Len, plainText, sizeof(plainText)/2));
    ASSERT_EQ (out_Len, 0);
    ASSERT_FALSE(EVP_EncryptFinal(ctx, out, &out_Len));
    ASSERT_EQ(out_Len, 0);
}
TEST_F (AES_128_ECB_Testing, Testing_4_on_Pading_With_Multiply) {
    ASSERT_EQ(EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key,  iv), 1);
    ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx, 1));
    ASSERT_TRUE(EVP_EncryptUpdate(ctx, out, &out_Len, plainText, sizeof(plainText)/2));
    ASSERT_EQ (out_Len, 0);
    ASSERT_TRUE(EVP_EncryptFinal(ctx, out, &out_Len));
    ASSERT_EQ(out_Len, 16);

    ASSERT_EQ(EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv), 1);
    ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx, 1));
    ASSERT_TRUE(EVP_DecryptUpdate(ctx, out, &out_Len, out, sizeof(out)));
    ASSERT_EQ (out_Len, 0);
    ASSERT_TRUE (EVP_DecryptFinal(ctx, out, &out_Len));
    ASSERT_EQ (out_Len, 8);

}
int main(int argc, char *argv[]){
    ::testing::InitGoogleTest(&argc, const_cast<char**>(argv));
    return RUN_ALL_TESTS();
}
