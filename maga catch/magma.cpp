#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
typedef uint8_t substitution_t[128];
substitution_t pi = {
	0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1,
	0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf,
	0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0,
	0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb,
	0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc,
	0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0,
	0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7,
	0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2
};
void magma_round(uint32_t round_key, uint32_t* a1, uint32_t a0)
{
	uint32_t g = a0 + round_key;
	
	uint32_t t =
		  ((pi[0   + ((g & 0x0000000f) >>  0)]) <<  0)
		| ((pi[16  + ((g & 0x000000f0) >>  4)]) <<  4)
		| ((pi[32  + ((g & 0x00000f00) >>  8)]) <<  8)
		| ((pi[48  + ((g & 0x0000f000) >> 12)]) << 12)
		| ((pi[64  + ((g & 0x000f0000) >> 16)]) << 16)
		| ((pi[80  + ((g & 0x00f00000) >> 20)]) << 20)
		| ((pi[96  + ((g & 0x0f000000) >> 24)]) << 24)
		| ((pi[112 + ((g & 0xf0000000) >> 28)]) << 28);
	
	*a1 ^= ((t << 11) | (t >> 21));
}
uint64_t magma_encrypt_block(uint32_t* key, uint64_t block)
{
	uint32_t a0 = (block      ) & 0xffffffff;
	uint32_t a1 = (block >> 32) & 0xffffffff;
	magma_round(key[0], &a1, a0);
	magma_round(key[1], &a0, a1);
	magma_round(key[2], &a1, a0);
	magma_round(key[3], &a0, a1);
	magma_round(key[4], &a1, a0);
	magma_round(key[5], &a0, a1);
	magma_round(key[6], &a1, a0);
	magma_round(key[7], &a0, a1);
	magma_round(key[0], &a1, a0);
	magma_round(key[1], &a0, a1);
	magma_round(key[2], &a1, a0);
	magma_round(key[3], &a0, a1);
	magma_round(key[4], &a1, a0);
	magma_round(key[5], &a0, a1);
	magma_round(key[6], &a1, a0);
	magma_round(key[7], &a0, a1);
	magma_round(key[0], &a1, a0);
	magma_round(key[1], &a0, a1);
	magma_round(key[2], &a1, a0);
	magma_round(key[3], &a0, a1);
	magma_round(key[4], &a1, a0);
	magma_round(key[5], &a0, a1);
	magma_round(key[6], &a1, a0);
	magma_round(key[7], &a0, a1);
	magma_round(key[7], &a1, a0);
	magma_round(key[6], &a0, a1);
	magma_round(key[5], &a1, a0);
	magma_round(key[4], &a0, a1);
	magma_round(key[3], &a1, a0);
	magma_round(key[2], &a0, a1);
	magma_round(key[1], &a1, a0);
	magma_round(key[0], &a0, a1);
	return ((uint64_t)a0 << 32) | (uint64_t)a1;
}
uint64_t magma_decrypt_block(uint32_t* key, uint64_t block)
{
	uint32_t a0 = (block      ) & 0xffffffff;
	uint32_t a1 = (block >> 32) & 0xffffffff;
	magma_round(key[0], &a1, a0);
	magma_round(key[1], &a0, a1);
	magma_round(key[2], &a1, a0);
	magma_round(key[3], &a0, a1);
	magma_round(key[4], &a1, a0);
	magma_round(key[5], &a0, a1);
	magma_round(key[6], &a1, a0);
	magma_round(key[7], &a0, a1);
	magma_round(key[7], &a1, a0);
	magma_round(key[6], &a0, a1);
	magma_round(key[5], &a1, a0);
	magma_round(key[4], &a0, a1);
	magma_round(key[3], &a1, a0);
	magma_round(key[2], &a0, a1);
	magma_round(key[1], &a1, a0);
	magma_round(key[0], &a0, a1);
	magma_round(key[7], &a1, a0);
	magma_round(key[6], &a0, a1);
	magma_round(key[5], &a1, a0);
	magma_round(key[4], &a0, a1);
	magma_round(key[3], &a1, a0);
	magma_round(key[2], &a0, a1);
	magma_round(key[1], &a1, a0);
	magma_round(key[0], &a0, a1);
	magma_round(key[7], &a1, a0);
	magma_round(key[6], &a0, a1);
	magma_round(key[5], &a1, a0);
	magma_round(key[4], &a0, a1);
	magma_round(key[3], &a1, a0);
	magma_round(key[2], &a0, a1);
	magma_round(key[1], &a1, a0);
	magma_round(key[0], &a0, a1);
	return ((uint64_t)a0 << 32) | (uint64_t)a1;
}

TEST_CASE( "Factorials are computed", "[factorial]" ) {
    uint32_t key[8] = {
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    };
    uint64_t openText = 0xfedcba9876543210;
    uint64_t cipherText = 0x4ee901e5c2d8ca3d;
    REQUIRE(magma_encrypt_block(key,openText) == cipherText);
    REQUIRE(magma_decrypt_block(key,cipherText) == openText);

}