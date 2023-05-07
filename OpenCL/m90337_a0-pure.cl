/**
 * Author......: siddhartha
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

#define BYTE_SWAP_U32(n) \
    (((n>>24)&0xff) | ((n<<8)&0xff0000) | ((n>>8)&0xff00) | ((n<<24)&0xff000000))
#define MAKE_U64(n,m) \
    ((n << 32) | (m & 0xffffffff))
#define NIBBLE(a, n) \
    ((a >> (60 - ((n & 0x0f) << 2))) & 0x0f)
#define REVERSE_BITS(n) \
    ((c_BitReverseTable256[n & 0xff] << 24) | \
    (c_BitReverseTable256[(n >> 8) & 0xff] << 16) | \
    (c_BitReverseTable256[(n >> 16) & 0xff] << 8) | \
    (c_BitReverseTable256[(n >> 24) & 0xff]))

#define ENCRYPT(l, r, k) \
    (l ^= c_SPtrans[0][((r ^ k[0]) >> 2) & 0x3f] ^ \
    c_SPtrans[2][((r ^ k[0]) >> 10) & 0x3f] ^ \
    c_SPtrans[4][((r ^ k[0]) >> 18) & 0x3f] ^ \
    c_SPtrans[6][((r ^ k[0]) >> 26) & 0x3f] ^ \
    c_SPtrans[1][((hc_rotr32(r, 4) ^ k[1]) >> 2) & 0x3f] ^ \
    c_SPtrans[3][((hc_rotr32(r, 4) ^ k[1]) >> 10) & 0x3f] ^ \
    c_SPtrans[5][((hc_rotr32(r, 4) ^ k[1]) >> 18) & 0x3f] ^ \
    c_SPtrans[7][((hc_rotr32(r, 4) ^ k[1]) >> 26) & 0x3f])
    
 #define SET_KEY1(k, n) \
    (((NIBBLE(k, n) >> 2 | (NIBBLE(k, n + 13) << 2)) & 0x3f)   | \
        (((NIBBLE(k, n + 11) >> 2 | (NIBBLE(k, n + 6) << 2)) & 0x3f) << 8)  | \
        (((NIBBLE(k, n + 3) >> 2 | (NIBBLE(k, n + 10) << 2)) & 0x3f) << 16) | \
        (((NIBBLE(k, n + 8) >> 2 | (NIBBLE(k, n + 1) << 2)) & 0x3f) << 24))

#define SET_KEY0(k, n) \
    (((NIBBLE(k, n + 9) | (NIBBLE(k, n) << 4)) & 0x3f)  | \
    (((NIBBLE(k, n + 2) | (NIBBLE(k, n + 11) << 4)) & 0x3f) << 8)   | \
    (((NIBBLE(k, n + 14) | (NIBBLE(k, n + 3) << 4)) & 0x3f) << 16)  | \
    (((NIBBLE(k, n + 5) | (NIBBLE(k, n + 8) << 4)) & 0x3f) << 24))

typedef struct StuffItDESKeySchedule
{
	u32a subKeys[16][2];
} StuffItDESKeySchedule;

CONSTANT_VK u8 c_BitReverseTable256[] =
{
	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
	0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, 0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
	0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
	0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
	0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, 0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
	0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
	0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
	0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
	0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
	0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
	0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
	0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, 0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
	0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
	0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb, 0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
	0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
	0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff
};

CONSTANT_VK u32a c_SPtrans[8][64] =
{
	{
		0x02080800, 0x00080000, 0x02000002, 0x02080802, 0x02000000, 0x00080802, 0x00080002, 0x02000002,
		0x00080802, 0x02080800, 0x02080000, 0x00000802, 0x02000802, 0x02000000, 0x00000000, 0x00080002,
		0x00080000, 0x00000002, 0x02000800, 0x00080800, 0x02080802, 0x02080000, 0x00000802, 0x02000800,
		0x00000002, 0x00000800, 0x00080800, 0x02080002, 0x00000800, 0x02000802, 0x02080002, 0x00000000,
		0x00000000, 0x02080802, 0x02000800, 0x00080002, 0x02080800, 0x00080000, 0x00000802, 0x02000800,
		0x02080002, 0x00000800, 0x00080800, 0x02000002, 0x00080802, 0x00000002, 0x02000002, 0x02080000,
		0x02080802, 0x00080800, 0x02080000, 0x02000802, 0x02000000, 0x00000802, 0x00080002, 0x00000000,
		0x00080000, 0x02000000, 0x02000802, 0x02080800, 0x00000002, 0x02080002, 0x00000800, 0x00080802
	},
	{
		0x40108010, 0x00000000, 0x00108000, 0x40100000, 0x40000010, 0x00008010, 0x40008000, 0x00108000,
		0x00008000, 0x40100010, 0x00000010, 0x40008000, 0x00100010, 0x40108000, 0x40100000, 0x00000010,
		0x00100000, 0x40008010, 0x40100010, 0x00008000, 0x00108010, 0x40000000, 0x00000000, 0x00100010,
		0x40008010, 0x00108010, 0x40108000, 0x40000010,	0x40000000, 0x00100000, 0x00008010, 0x40108010,
		0x00100010, 0x40108000, 0x40008000, 0x00108010,	0x40108010, 0x00100010, 0x40000010, 0x00000000,
		0x40000000, 0x00008010, 0x00100000, 0x40100010,	0x00008000, 0x40000000, 0x00108010, 0x40008010,
		0x40108000, 0x00008000, 0x00000000, 0x40000010,	0x00000010, 0x40108010, 0x00108000, 0x40100000,
		0x40100010, 0x00100000, 0x00008010, 0x40008000,	0x40008010, 0x00000010, 0x40100000, 0x00108000
	},
	{
		0x04000001, 0x04040100, 0x00000100, 0x04000101,	0x00040001, 0x04000000, 0x04000101, 0x00040100,
		0x04000100, 0x00040000, 0x04040000, 0x00000001,	0x04040101, 0x00000101, 0x00000001, 0x04040001,
		0x00000000, 0x00040001, 0x04040100, 0x00000100,	0x00000101, 0x04040101, 0x00040000, 0x04000001,
		0x04040001, 0x04000100, 0x00040101, 0x04040000,	0x00040100, 0x00000000, 0x04000000, 0x00040101,
		0x04040100, 0x00000100, 0x00000001, 0x00040000,	0x00000101, 0x00040001, 0x04040000, 0x04000101,
		0x00000000, 0x04040100, 0x00040100, 0x04040001,	0x00040001, 0x04000000, 0x04040101, 0x00000001,
		0x00040101, 0x04000001, 0x04000000, 0x04040101,	0x00040000, 0x04000100, 0x04000101, 0x00040100,
		0x04000100, 0x00000000, 0x04040001, 0x00000101,	0x04000001, 0x00040101, 0x00000100, 0x04040000
	},
	{
		0x00401008, 0x10001000, 0x00000008, 0x10401008,	0x00000000, 0x10400000, 0x10001008, 0x00400008,
		0x10401000, 0x10000008, 0x10000000, 0x00001008,	0x10000008, 0x00401008, 0x00400000, 0x10000000,
		0x10400008, 0x00401000, 0x00001000, 0x00000008,	0x00401000, 0x10001008, 0x10400000, 0x00001000,
		0x00001008, 0x00000000, 0x00400008, 0x10401000,	0x10001000, 0x10400008, 0x10401008, 0x00400000,
		0x10400008, 0x00001008, 0x00400000, 0x10000008,	0x00401000, 0x10001000, 0x00000008, 0x10400000,
		0x10001008, 0x00000000, 0x00001000, 0x00400008,	0x00000000, 0x10400008, 0x10401000, 0x00001000,
		0x10000000, 0x10401008, 0x00401008, 0x00400000,	0x10401008, 0x00000008, 0x10001000, 0x00401008,
		0x00400008, 0x00401000, 0x10400000, 0x10001008,	0x00001008, 0x10000000, 0x10000008, 0x10401000
	},
	{
		0x08000000, 0x00010000, 0x00000400, 0x08010420,	0x08010020, 0x08000400, 0x00010420, 0x08010000,
		0x00010000, 0x00000020, 0x08000020, 0x00010400, 0x08000420, 0x08010020, 0x08010400, 0x00000000,
		0x00010400, 0x08000000, 0x00010020, 0x00000420,	0x08000400, 0x00010420, 0x00000000, 0x08000020,
		0x00000020, 0x08000420, 0x08010420, 0x00010020,	0x08010000, 0x00000400, 0x00000420, 0x08010400,
		0x08010400, 0x08000420, 0x00010020, 0x08010000,	0x00010000, 0x00000020, 0x08000020, 0x08000400,
		0x08000000, 0x00010400, 0x08010420, 0x00000000,	0x00010420, 0x08000000, 0x00000400, 0x00010020,
		0x08000420, 0x00000400, 0x00000000, 0x08010420,	0x08010020, 0x08010400, 0x00000420, 0x00010000,
		0x00010400, 0x08010020, 0x08000400, 0x00000420,	0x00000020, 0x00010420, 0x08010000, 0x08000020
	},
	{
		0x80000040, 0x00200040, 0x00000000, 0x80202000,	0x00200040, 0x00002000, 0x80002040, 0x00200000,
		0x00002040, 0x80202040, 0x00202000, 0x80000000,	0x80002000, 0x80000040, 0x80200000, 0x00202040,
		0x00200000, 0x80002040, 0x80200040, 0x00000000,	0x00002000, 0x00000040, 0x80202000, 0x80200040,
		0x80202040, 0x80200000, 0x80000000, 0x00002040,	0x00000040, 0x00202000, 0x00202040, 0x80002000,
		0x00002040, 0x80000000, 0x80002000, 0x00202040,	0x80202000, 0x00200040, 0x00000000, 0x80002000,
		0x80000000, 0x00002000, 0x80200040, 0x00200000,	0x00200040, 0x80202040, 0x00202000, 0x00000040,
		0x80202040, 0x00202000, 0x00200000, 0x80002040,	0x80000040, 0x80200000, 0x00202040, 0x00000000,
		0x00002000, 0x80000040, 0x80002040, 0x80202000,	0x80200000, 0x00002040, 0x00000040, 0x80200040
	},
	{
		0x00004000, 0x00000200, 0x01000200, 0x01000004, 0x01004204, 0x00004004, 0x00004200, 0x00000000,
		0x01000000, 0x01000204, 0x00000204, 0x01004000,	0x00000004, 0x01004200, 0x01004000, 0x00000204,
		0x01000204, 0x00004000, 0x00004004, 0x01004204, 0x00000000, 0x01000200, 0x01000004, 0x00004200,
		0x01004004, 0x00004204, 0x01004200, 0x00000004, 0x00004204, 0x01004004, 0x00000200, 0x01000000,
		0x00004204, 0x01004000, 0x01004004, 0x00000204, 0x00004000, 0x00000200, 0x01000000, 0x01004004,
		0x01000204, 0x00004204, 0x00004200, 0x00000000,	0x00000200, 0x01000004, 0x00000004, 0x01000200,
		0x00000000, 0x01000204, 0x01000200, 0x00004200,	0x00000204, 0x00004000, 0x01004204, 0x01000000,
		0x01004200, 0x00000004, 0x00004004, 0x01004204, 0x01000004, 0x01004200, 0x01004000, 0x00004004
	},
	{
		0x20800080, 0x20820000, 0x00020080, 0x00000000,	0x20020000, 0x00800080, 0x20800000, 0x20820080,
		0x00000080, 0x20000000, 0x00820000, 0x00020080,	0x00820080, 0x20020080, 0x20000080, 0x20800000,
		0x00020000, 0x00820080, 0x00800080, 0x20020000,	0x20820080, 0x20000080, 0x00000000, 0x00820000,
		0x20000000, 0x00800000, 0x20020080, 0x20800080,	0x00800000, 0x00020000, 0x20820000, 0x00000080,
		0x00800000, 0x00020000, 0x20000080, 0x20820080,	0x00020080, 0x20000000, 0x00000000, 0x00820000,
		0x20800080, 0x20020080, 0x20020000, 0x00800080,	0x20820000, 0x00000080, 0x00800080, 0x20020000,
		0x20820080, 0x00800000, 0x20800000, 0x20000080,	0x00820000, 0x00020080, 0x20020080, 0x20800000,
		0x00000080, 0x20820000, 0x00820080, 0x00000000,	0x20000000, 0x20800080, 0x00020000, 0x00820080
	}
};


DECLSPEC void StuffItDESSetKey(u64x key, StuffItDESKeySchedule *ks) {  
    u32x subKey1 = SET_KEY1(key, 0);
    u32x subKey0 = SET_KEY0(key, 0);
    ks->subKeys[0][0] = REVERSE_BITS(subKey1);
    ks->subKeys[0][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 1);
    subKey0 = SET_KEY0(key, 1);
    ks->subKeys[1][0] = REVERSE_BITS(subKey1);
    ks->subKeys[1][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 2);
    subKey0 = SET_KEY0(key, 2);
    ks->subKeys[2][0] = REVERSE_BITS(subKey1);
    ks->subKeys[2][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 3);
    subKey0 = SET_KEY0(key, 3);
    ks->subKeys[3][0] = REVERSE_BITS(subKey1);
    ks->subKeys[3][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 4);
    subKey0 = SET_KEY0(key, 4);
    ks->subKeys[4][0] = REVERSE_BITS(subKey1);
    ks->subKeys[4][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 5);
    subKey0 = SET_KEY0(key, 5);
    ks->subKeys[5][0] = REVERSE_BITS(subKey1);
    ks->subKeys[5][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 6);
    subKey0 = SET_KEY0(key, 6);
    ks->subKeys[6][0] = REVERSE_BITS(subKey1);
    ks->subKeys[6][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 7);
    subKey0 = SET_KEY0(key, 7);
    ks->subKeys[7][0] = REVERSE_BITS(subKey1);
    ks->subKeys[7][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 8);
    subKey0 = SET_KEY0(key, 8);
    ks->subKeys[8][0] = REVERSE_BITS(subKey1);
    ks->subKeys[8][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 9);
    subKey0 = SET_KEY0(key, 9);
    ks->subKeys[9][0] = REVERSE_BITS(subKey1);
    ks->subKeys[9][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 10);
    subKey0 = SET_KEY0(key, 10);
    ks->subKeys[10][0] = REVERSE_BITS(subKey1);
    ks->subKeys[10][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 11);
    subKey0 = SET_KEY0(key, 11);
    ks->subKeys[11][0] = REVERSE_BITS(subKey1);
    ks->subKeys[11][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 12);
    subKey0 = SET_KEY0(key, 12);
    ks->subKeys[12][0] = REVERSE_BITS(subKey1);
    ks->subKeys[12][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 13);
    subKey0 = SET_KEY0(key, 13);
    ks->subKeys[13][0] = REVERSE_BITS(subKey1);
    ks->subKeys[13][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 14);
    subKey0 = SET_KEY0(key, 14);
    ks->subKeys[14][0] = REVERSE_BITS(subKey1);
    ks->subKeys[14][1] = REVERSE_BITS(subKey0);
    
    subKey1 = SET_KEY1(key, 15);
    subKey0 = SET_KEY0(key, 15);
    ks->subKeys[15][0] = REVERSE_BITS(subKey1);
    ks->subKeys[15][1] = REVERSE_BITS(subKey0);
}

DECLSPEC void StuffItDESCrypt(u32a *data, StuffItDESKeySchedule *ks, u32 enc) {
	u32x l = REVERSE_BITS(data[0]);
	u32x r = REVERSE_BITS(data[1]);

	r = hc_rotr32(r, 29);
	l = hc_rotr32(l, 29);

	if (enc)
    {
		ENCRYPT(l, r, ks->subKeys[0]);
		ENCRYPT(r, l, ks->subKeys[1]);
		ENCRYPT(l, r, ks->subKeys[2]);
		ENCRYPT(r, l, ks->subKeys[3]);
		ENCRYPT(l, r, ks->subKeys[4]);
		ENCRYPT(r, l, ks->subKeys[5]);
		ENCRYPT(l, r, ks->subKeys[6]);
		ENCRYPT(r, l, ks->subKeys[7]);
		ENCRYPT(l, r, ks->subKeys[8]);
		ENCRYPT(r, l, ks->subKeys[9]);
		ENCRYPT(l, r, ks->subKeys[10]);
		ENCRYPT(r, l, ks->subKeys[11]);
		ENCRYPT(l, r, ks->subKeys[12]);
		ENCRYPT(r, l, ks->subKeys[13]);
		ENCRYPT(l, r, ks->subKeys[14]);
		ENCRYPT(r, l, ks->subKeys[15]);
	}
	else  {
		ENCRYPT(l, r, ks->subKeys[15]);
		ENCRYPT(r, l, ks->subKeys[14]);
		ENCRYPT(l, r, ks->subKeys[13]);
		ENCRYPT(r, l, ks->subKeys[12]);
		ENCRYPT(l, r, ks->subKeys[11]);
		ENCRYPT(r, l, ks->subKeys[10]);
		ENCRYPT(l, r, ks->subKeys[9]);
		ENCRYPT(r, l, ks->subKeys[8]);
		ENCRYPT(l, r, ks->subKeys[7]);
		ENCRYPT(r, l, ks->subKeys[6]);
		ENCRYPT(l, r, ks->subKeys[5]);
		ENCRYPT(r, l, ks->subKeys[4]);
		ENCRYPT(l, r, ks->subKeys[3]);
		ENCRYPT(r, l, ks->subKeys[2]);
		ENCRYPT(l, r, ks->subKeys[1]);
		ENCRYPT(r, l, ks->subKeys[0]);
	}

	l = hc_rotr32(l, 3);
	r = hc_rotr32(r, 3);

	data[0] = REVERSE_BITS(r);
	data[1] = REVERSE_BITS(l);
}

KERNEL_FQ void m90337_mxx (KERN_ATTR_RULES ())
{
  // no support
}

KERNEL_FQ void m90337_sxx (KERN_ATTR_RULES ())
{
    const u64 gid = get_global_id (0);
    const u64 lid = get_local_id (0);
    const u64 lsz = get_local_size (0);

    LOCAL_VK u32 s_SPtrans[8][64];

    for (u32 i = lid; i < 64; i += lsz)
    {
        s_SPtrans[0][i] = c_SPtrans[0][i];
        s_SPtrans[1][i] = c_SPtrans[1][i];
        s_SPtrans[2][i] = c_SPtrans[2][i];
        s_SPtrans[3][i] = c_SPtrans[3][i];
        s_SPtrans[4][i] = c_SPtrans[4][i];
        s_SPtrans[5][i] = c_SPtrans[5][i];
        s_SPtrans[6][i] = c_SPtrans[6][i];
        s_SPtrans[7][i] = c_SPtrans[7][i];
    }
    
    struct StuffItDESKeySchedule initialKeySchedule =
    {
        {
            {0x2c581460, 0x904c7ca0},
            {0x1cf8b450, 0x58c0f068},
            {0x3cc48c70, 0xd42808e4},
            {0x00e4ac48, 0x3ca4841c},
            {0xa0d49ce8, 0xb06c4c90},
            {0x90347cd8, 0x78e0c058},
            {0xb00c40f8, 0xf41828d4},
            {0x882c60c4, 0x0c94a43c},
            {0x681c5024, 0x805c6cb0},
            {0x58bcf014, 0x48d0e078},
            {0x7880c834, 0xc43818f4},
            {0x44a0e80c, 0x2cb4940c},
            {0xe490d8ac, 0xa07c5c80},
            {0xd470389c, 0x68f0d048},
            {0xf44804bc, 0xe40838c4},
            {0xcc682480, 0x1c84b42c}
        }
    };

    SYNC_THREADS ();

    if (gid >= GID_CNT) return;

    COPY_PW (pws[gid]);

    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
        pw_t tmp = PASTE_PW;

        tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

        u32a data[16];
        
        #define IKEY1 0x01234567ULL
        #define IKEY2 0x89abcdefULL

        for (u32 i = 0 ; i < (tmp.pw_len >> 2) + 1 ; i += 2)
        {
            if (i > 1) {
                data[0] ^= BYTE_SWAP_U32(tmp.i[i]);
                data[1] ^= BYTE_SWAP_U32(tmp.i[i + 1]);
            } else {
                data[0] = BYTE_SWAP_U32(tmp.i[i]) ^ IKEY1;
                data[1] = BYTE_SWAP_U32(tmp.i[i + 1]) ^ IKEY2;
            }
            
            StuffItDESCrypt(data, &initialKeySchedule, 1);
        }
           
        StuffItDESKeySchedule keySchedule;
        u64x dataKey = MAKE_U64((u64)data[0], (u64)data[1]);
        u32a digest[2] =
        {
            BYTE_SWAP_U32(digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0]),
            BYTE_SWAP_U32(digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1])
        };
                
        StuffItDESSetKey(dataKey, &keySchedule);
        StuffItDESCrypt(digest, &keySchedule, 0);

        u32a verify[2];

        verify[0] = digest[0];
        verify[1] = 4;

        StuffItDESSetKey(dataKey, &keySchedule);
        StuffItDESCrypt(verify, &keySchedule, 1);

        const u32 search[4] =
        {
            digest[1],
            0,
            0,
            0
        };

        COMPARE_S_SIMD (verify[1], 0, 0, 0);
    }
}
