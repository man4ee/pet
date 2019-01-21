#include <iostream>
#include <cstdlib>
#include <gtest/gtest.h>
#include <openssl/bn.h>

using namespace std;




class Test_BigNumbers : public ::testing::Test 
{
protected:
	BIGNUM* a;
    BIGNUM* b;
    BIGNUM* r;
    BIGNUM* c;
    BN_CTX *bn_ctx;

	virtual void SetUp()    
	{ 
		a = BN_new();
        b = BN_new();
        r = BN_new();
        c = BN_new();
        bn_ctx = BN_CTX_new();
	}
	
    virtual void TearDown() 
	{ 
		BN_clear_free(a);
        BN_clear_free(b);
        BN_clear_free(r);
        BN_clear_free(c);
        BN_CTX_free (bn_ctx);
	}
};


TEST_F(Test_BigNumbers , Test_add)
{
    BN_dec2bn(&a, "100000000000000000000");
    BN_dec2bn(&b, "100000000000000000000");
    BN_add (r , a , b);
    ASSERT_STREQ(BN_bn2dec (r) , "200000000000000000000");
}

TEST_F(Test_BigNumbers , Test_sub)
{
    BN_dec2bn(&a, "100000000000000000000");
    BN_dec2bn(&b, "100000000000000000000");
    BN_sub (r , a , b);
    ASSERT_STREQ(BN_bn2dec (r) , "0");
}

TEST_F(Test_BigNumbers , Test_mul)
{
    BN_dec2bn(&a, "333333333333");
    BN_dec2bn(&b, "333333333333");
    BN_mul (r , a , b,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "111111111110888888888889");
}

TEST_F(Test_BigNumbers , Test_sqr)
{
    BN_dec2bn(&a, "10000000000000000");
    BN_sqr (r ,a ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "100000000000000000000000000000000");
}

TEST_F(Test_BigNumbers , Test_div)
{
    BN_dec2bn(&a, "10000000000000000");
    BN_dec2bn(&b, "10000000000000000");
    BN_div (c, r , a ,b ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "0");
    ASSERT_STREQ(BN_bn2dec (c) , "1");
}

TEST_F(Test_BigNumbers , Test_div2)
{
    BN_dec2bn(&a, "10000000000000001");
    BN_dec2bn(&b, "10000000000000000");
    BN_div (c, r , a ,b ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "1");
    ASSERT_STREQ(BN_bn2dec (c) , "1");
}

TEST_F(Test_BigNumbers , Test_mod)
{
    BN_dec2bn(&a, "10000000000000002");
    BN_dec2bn(&b, "10000000000000000");
    BN_mod ( r , a ,b ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "2");
}

TEST_F(Test_BigNumbers , Test_mod_add)
{
    BN_dec2bn(&a, "10000000000000002");
    BN_dec2bn(&b, "10000000000000000");
    BN_dec2bn(&c, "20000000000000000");
    BN_mod_add ( r , a ,b, c ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "2");
}

TEST_F(Test_BigNumbers , Test_mod_sub)
{
    BN_dec2bn(&a, "10000000000000002");
    BN_dec2bn(&b, "-10000000000000000");
    BN_dec2bn(&c, "20000000000000000");
    BN_mod_sub ( r , a ,b, c ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "2");
}

TEST_F(Test_BigNumbers , Test_mod_mul)
{
    BN_dec2bn(&a, "10000000000000002");
    BN_dec2bn(&b, "10000000000000002");
    BN_dec2bn(&c, "10000000000000004000000000000000");
    BN_mod_mul ( r , a ,b, c ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "4");
}

TEST_F(Test_BigNumbers , Test_mod_sqr)
{
    BN_dec2bn(&a, "10000000000000002");
    BN_dec2bn(&c, "10000000000000004000000000000000");
    BN_mod_sqr ( r , a, c ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "4");
}

TEST_F(Test_BigNumbers , Test_mod_exp)
{
    BN_dec2bn(&a, "10000000000000002");
    BN_dec2bn(&b, "3");
    BN_dec2bn(&c, "100000000000000060000000000000012000000000000000");
    BN_mod_exp ( r , a, b, c ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "8");
}

TEST_F(Test_BigNumbers , Test_exp)
{
    BN_dec2bn(&a, "10000000000000002");
    BN_dec2bn(&b, "3");
    BN_exp ( r , a, b ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "1000000000000000600000000000000120000000000000008");
}

TEST_F(Test_BigNumbers , Test_gcd)
{
    BN_dec2bn(&a, "10000000000000003");
    BN_dec2bn(&b, "3");
    BN_gcd ( r , a, b ,bn_ctx);
    ASSERT_STREQ(BN_bn2dec (r) , "1");
}

TEST_F(Test_BigNumbers , Test_cmp)
{
    BN_dec2bn(&a, "10000000000000003");
    BN_dec2bn(&b, "3");
    BN_dec2bn(&c, "3");
    ASSERT_EQ(BN_cmp (a, b) , 1);
    ASSERT_EQ(BN_cmp (b, a) , -1);
    ASSERT_EQ(BN_cmp (c, b) , 0);
}


int main(int argc, char *argv[]){
    ::testing::InitGoogleTest(&argc, const_cast<char**>(argv));
    return RUN_ALL_TESTS();
}
