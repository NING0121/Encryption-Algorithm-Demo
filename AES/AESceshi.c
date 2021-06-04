#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <memory.h>  
#include <time.h>  
#include <stdint.h>    
#define PLAIN_FILE_OPEN_ERROR -1  
#define KEY_FILE_OPEN_ERROR -2  
#define CIPHER_FILE_OPEN_ERROR -3  
#define OK 1 
#define BLOCKSIZE 16  //AES-128分组长度为16字节

// uint8_t y[4] -> uint32_t x
#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

// uint32_t x -> uint8_t y[4]
#define STORE32H(x, y) \
  do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
       (y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

// 从uint32_t x中提取从低位开始的第n个字节
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
// 字节替换然后循环左移1位
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                ((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

// uint32_t x循环左移n位
#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))
// uint32_t x循环右移n位
#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))

const char* DES_MODE[] = { "ECB","CBC","CFB","OFB" };
char* plainfile = NULL;//明文文件 
char* keyfile = NULL;//秘钥文件 
char* vifile = NULL;//初始化向量文件 
char* mode = NULL;//模式 
char* cipherfile = NULL;//密文文件 
char* plaintext = NULL;//明文 
char* keytext = NULL;//秘钥 
char* vitext = NULL;//初始化向量 
char* ciphertext = NULL;//密文 
char miwen[64];//加密出来的密文的char 
char jiemimingwen[64];//解密出来的明文的char 
void hextochar(int a,const b,int c);//16进制转换成字符 
void charToBit(char * msg, int* msgBit);//单个字节的转换二进制 
void charToBit1(char * msg, int* msgBit);//两个字节的转换二进制 
////char vitextchange[16];
int b1(int bit[8],char ch[2]);	
typedef struct{
    uint32_t eK[44], dK[44];    // encKey, decKey
    int Nr; // 10 rounds
}AesKey;

// AES-128轮常量
static const uint32_t rcon[10] = {
        0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL,
        0x20000000UL, 0x40000000UL, 0x80000000UL, 0x1B000000UL, 0x36000000UL
};
// AES的S盒
unsigned char S[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

//AES的逆S盒
unsigned char inv_S[256] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// 将输入的16数组转换成4*4的矩阵形式 
int loadStateArray(uint8_t (*state)[4], const uint8_t *in) {
	int i,j; 
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[j][i] = *in++;   //矩阵形式的赋值 
        }
    }
    return 0;
}

// 将输入的4*4的矩阵形式转换成16数组形式 
int storeStateArray(uint8_t (*state)[4], uint8_t *out) {
	int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            *out++ = state[j][i]; 
        }
    }
    return 0;
}

//秘钥扩展
int keyExpansion(const uint8_t *key, uint32_t keyLen, AesKey *aesKey) {
    int i,j;
    if (NULL == key || NULL == aesKey){
        printf("秘钥扩展失败\n");
        return -1;
    }
    if (keyLen != 16){
        printf("秘钥长度 = %d, 不支持转换\n", keyLen);
        return -1;
    }
    uint32_t *w = aesKey->eK;  //加密秘钥
    uint32_t *v = aesKey->dK;  //解密秘钥
    /* W[0-3] */
    //0-3个秘钥置换 
    for (i = 0; i < 4; ++i) {
        LOAD32H(w[i], key + 4*i);
    }
    /* W[4-43] */
    //4-43个秘钥置换 
    for (i = 0; i < 10; ++i) {
        w[4] = w[0] ^ MIX(w[3]) ^ rcon[i];
        w[5] = w[1] ^ w[4];
        w[6] = w[2] ^ w[5];
        w[7] = w[3] ^ w[6];
        w += 4;
    }
    w = aesKey->eK+44 - 4;
    //解密秘钥矩阵为加密秘钥矩阵的倒序，方便使用，把ek的11个矩阵倒序排列分配给dk作为解密秘钥
    //即dk[0-3]=ek[41-44], dk[4-7]=ek[37-40]... dk[41-44]=ek[0-3]
    for (j = 0; j < 11; ++j) {

        for ( i = 0; i < 4; ++i) {
            v[i] = w[i];
        }
        w -= 4;
        v += 4;
    }

    return 0;
}

// 轮秘钥加
int addRoundKey(uint8_t (*state)[4], const uint32_t *key) {
    uint8_t k[4][4];
    int i,j;
    /* i: 行, j: 列 */
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            k[i][j] = (uint8_t) BYTE(key[j], 3 - i);  /* 把 uint32 key[4] 先转换为矩阵 uint8 k[4][4] */
            state[i][j] ^= k[i][j];
        }
    }
    return 0;
}

//字节替换
int subBytes(uint8_t (*state)[4]) {
    /* i: 行, j: 列 */
    int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = S[state[i][j]]; //直接使用原始字节作为S盒数据下标
        }
    }
    return 0;
}

//逆字节替换
int invSubBytes(uint8_t (*state)[4]) {
    /* i: 行, j: c列 */
    int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = inv_S[state[i][j]];//直接使用原始字节作为S盒数据下标
        }
    }
    return 0;
}

//行移位
int shiftRows(uint8_t (*state)[4]) {
    uint32_t block[4] = {0};
    int i;
    /* i: row */
    for (i = 0; i < 4; ++i) {
    //便于行循环移位，先把一行4字节拼成uint_32结构，移位后再转成独立的4个字节uint8_t
        LOAD32H(block[i], state[i]);
        block[i] = ROF32(block[i], 8*i);
        STORE32H(block[i], state[i]);
    }

    return 0;
}

//逆行移位
int invShiftRows(uint8_t (*state)[4]) {
    uint32_t block[4] = {0};
    int i;
    /* i: row */
    for (i = 0; i < 4; ++i) {
        LOAD32H(block[i], state[i]);
        block[i] = ROR32(block[i], 8*i);
        STORE32H(block[i], state[i]);
    }

    return 0;
}

// 两字节的伽罗华域乘法运算
uint8_t GMul(uint8_t u, uint8_t v) {
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; ++i) {
        if (u & 0x01) {    //
            p ^= v;
        }
        int flag = (v & 0x80);
        v <<= 1;
        if (flag) {
            v ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }

        u >>= 1;
    }

    return p;
}

// 列混合
int mixColumns(uint8_t (*state)[4]) {
    uint8_t tmp[4][4];
    int i,j;
    uint8_t M[4][4] = {{0x02, 0x03, 0x01, 0x01},
                       {0x01, 0x02, 0x03, 0x01},
                       {0x01, 0x01, 0x02, 0x03},
                       {0x03, 0x01, 0x01, 0x02}};

    /* copy state[4][4] to tmp[4][4] */
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j){
            tmp[i][j] = state[i][j];
        }
    }

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {  //伽罗华域加法和乘法
            state[i][j] = GMul(M[i][0], tmp[0][j]) ^ GMul(M[i][1], tmp[1][j])
                        ^ GMul(M[i][2], tmp[2][j]) ^ GMul(M[i][3], tmp[3][j]);
        }
    }

    return 0;
}

// 逆列混合
int invMixColumns(uint8_t (*state)[4]) {
    uint8_t tmp[4][4];
    int i,j;
    uint8_t M[4][4] = {{0x0E, 0x0B, 0x0D, 0x09},
                       {0x09, 0x0E, 0x0B, 0x0D},
                       {0x0D, 0x09, 0x0E, 0x0B},
                       {0x0B, 0x0D, 0x09, 0x0E}};  //使用列混合矩阵的逆矩阵

    /* copy state[4][4] to tmp[4][4] */
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j){
            tmp[i][j] = state[i][j];
        }
    }

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = GMul(M[i][0], tmp[0][j]) ^ GMul(M[i][1], tmp[1][j])
                          ^ GMul(M[i][2], tmp[2][j]) ^ GMul(M[i][3], tmp[3][j]);
        }
    }

    return 0;
}

// AES-128加密函数，输入key应为16字节长度，输入长度应该是16字节整倍数，pt代表明文，ct是输出，是十进制的表示，len是加密的长度 
int aesEncrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *pt, uint8_t *ct, uint32_t len) {
    AesKey aesKey;
    uint8_t *pos = ct;
    const uint32_t *rk = aesKey.eK;  //解密秘钥指针
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    int i,j;
    if (NULL == key || NULL == pt || NULL == ct){
        printf("出错啦！\n");
        return -1;
    }

    if (keyLen > 16){
        printf("秘钥的长度一定要是16位哦！\n");
        return -1;
    }

    if (len % BLOCKSIZE){
        printf("输入的字符长度不对哦！\n");
        return -1;
    }

    memcpy(actualKey, key, keyLen);
    keyExpansion(actualKey, 16, &aesKey);  // 秘钥扩展

	// 使用ECB模式循环加密多个分组长度的数据
    for (i = 0; i < len; i += BLOCKSIZE) {
		// 把16字节的明文转换为4x4状态矩阵来进行处理
        loadStateArray(state, pt);
        // 轮秘钥加
        addRoundKey(state, rk);

        for (j = 1; j < 10; ++j) {
            rk += 4;
            subBytes(state);   // 字节替换
            shiftRows(state);  // 行移位
            mixColumns(state); // 列混合
            addRoundKey(state, rk); // 轮秘钥加
        }

        subBytes(state);    // 字节替换
        shiftRows(state);  // 行移位
        // 此处不进行列混合
        addRoundKey(state, rk+4); // 轮秘钥加
		
		// 把4x4状态矩阵转换为uint8_t一维数组输出保存
        storeStateArray(state, pos);

        pos += BLOCKSIZE;  // 加密数据内存指针移动到下一个分组
        pt += BLOCKSIZE;   // 明文数据指针移动到下一个分组
        rk = aesKey.eK;    // 恢复rk指针到秘钥初始位置
    }
    return 0;
}

// AES128解密， 参数要求同加密
int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len) {
    AesKey aesKey;
    uint8_t *pos = pt;
    const uint32_t *rk = aesKey.dK;  //解密秘钥指针
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    int i,j;
    if (NULL == key || NULL == ct || NULL == pt){
        printf("程序出错啦！\n");
        return -1;
    }

    if (keyLen > 16){
        printf("秘钥长度一定要是16哦！\n");
        return -1;
    }

    if (len % BLOCKSIZE){
        printf("输入的长度不对哦！\n");
        return -1;
    }

    memcpy(actualKey, key, keyLen);
    keyExpansion(actualKey, 16, &aesKey);  //秘钥扩展，同加密

    for (i = 0; i < len; i += BLOCKSIZE) {
        // 把16字节的密文转换为4x4状态矩阵来进行处理
        loadStateArray(state, ct);
        // 轮秘钥加，同加密
        addRoundKey(state, rk);

        for (j = 1; j < 10; ++j) {
            rk += 4;
            invShiftRows(state);    // 逆行移位
            invSubBytes(state);     // 逆字节替换，这两步顺序可以颠倒
            addRoundKey(state, rk); // 轮秘钥加，同加密
            invMixColumns(state);   // 逆列混合
        }

        invSubBytes(state);   // 逆字节替换
        invShiftRows(state);  // 逆行移位
        // 此处没有逆列混合
        addRoundKey(state, rk+4);  // 轮秘钥加，同加密

        storeStateArray(state, pos);  // 保存明文数据
        pos += BLOCKSIZE;  // 输出数据内存指针移位分组长度
        ct += BLOCKSIZE;   // 输入数据内存指针移位分组长度
        rk = aesKey.dK;    // 恢复rk指针到秘钥初始位置
    }
    return 0;
}

//输出16进制 
void printHex(const uint8_t *ptr, int len, char *tag) {
	int i;
    printf("%s\ndata[%d]: ", tag, len);
    for (i = 0; i < len; ++i) {
        printf("%.2X ", *ptr++);
    }
    printf("\n");
}

//输出16进制 
void printhexin(int d,int i){
	int n,a1,count=0,j;//count 用于角标的计数，j 控制 for 循环 
	int a[100]; 
	a[0]=0;
	a[1]=0; 
    n=d;
	if(n==0) {
		a[0]=0;
		a[1]=0;
	}		
	while(n!=0) { 
		a1=n;
 		n=n/16;
  		a[count]=a1%16; 
  		count++; 
    } 
	hextochar(a[1],0,i);
	hextochar(a[0],1,i);
}

//16进制转换为2进制，c是位数 
void hextochar(int a,const int b,int c){
    		switch(a){
    			case 0:miwen[2*c+b]='0';
    			       break;
    			case 1:miwen[2*c+b]='1'; 
    			       break;
    			case 2:miwen[2*c+b]='2';
    			       break;
    			case 3:miwen[2*c+b]='3';
    			       break;
    			case 4:miwen[2*c+b]='4';
    			       break;
    			case 5:miwen[2*c+b]='5';
    			       break;
				case 6:miwen[2*c+b]='6';
    			       break;
    			case 7:miwen[2*c+b]='7';
    			       break;
    			case 8:miwen[2*c+b]='8';
    			       break;
    			case 9:miwen[2*c+b]='9';
    			       break;
    			case 10:miwen[2*c+b]='A';
    			       break;
    			case 11:miwen[2*c+b]='B';
    			       break;    			       
    			case 12:miwen[2*c+b]='C';
    			       break;
    			case 13:miwen[2*c+b]='D';
    			       break;
    			case 14:miwen[2*c+b]='E';
    			       break;
    			case 15:miwen[2*c+b]='F';
    			       break;
    			       
			}
//			printf("%c",miwen[2*c+b]);
		
}

void print_usage() {
	printf("\n非法输入,支持的参数有以下：\n-p plainfile 指定明文文件的位置和名称\n-k keyfile  指定密钥文件的位置和名称\n-v vifile  指定初始化向量文件的位置和名称\n-m mode  指定加密的操作模式(ECB,CBC,CFB,OFB)\n-c cipherfile 指定密文文件的位置和名称。\n");
	exit(-1);
}

bool readfile2memory(const char* filename, char** memory) {
	FILE* fp = NULL;
	int i; 
	fp = fopen(filename, "r");//打开文件 
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END);//设置文件指针位置 
	int size = ftell(fp);//得到文件位置指针当前位置相对于文件首的偏移字节数
	fseek(fp, 0, SEEK_SET);
	if (size % 2 != 0) {
		printf("%s:文件字节数不为偶数！\n", filename);
		fclose(fp);
		return false;
	}
	char* tmp = malloc(size);//分配内存 
	memset(tmp, 0, size);//给tmp清零 
	fread(tmp, size, 1, fp);
	if (ferror(fp)) {
		printf("读取%s出错了！\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}
	*memory = malloc(size / 2 + 1);
	memset(*memory, 0, size / 2 + 1);//给memory分配内存 
	char parsewalker[3] = { 0 };
	for (i = 0; i < size; i += 2) {
		parsewalker[0] = tmp[i];
		parsewalker[1] = tmp[i + 1];
		(*memory)[i / 2] = strtol(parsewalker, 0, 16);//扫描参数字符串，跳过前面的空格字符，直到遇上数字或正负符号才开始做转换，再遇到非数字或字符串结束时('\0')结束转换，并将结果返回。 
//		printf("debug info : %c\n", (*memory)[i / 2]);
	}

	free(tmp);

	return true;
}

void ECB(const char* plaintext, const char* keytext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
    int i;
    const uint8_t *data = (uint8_t*)plaintext;  
    uint8_t ct2[32] = {0};    //外部申请输出数据内存，用于存放加密后数据
    uint8_t plain2[32] = {0}; //外部申请输出数据内存，用于存放解密后数据
    //加密32字节明文
    aesEncrypt(keytext, 16, data, ct2, 32); //加密 
//    printHex(ct2, 32, "加密出来的结果：");//打印16进制 
    FILE* fp = fopen(cipherfile, "a");
    for(i=0;i<32;i++){
    	printhexin(ct2[i],i);
	}
	fwrite(miwen,sizeof(char),64,fp);
	fclose(fp);
///	printf("%s\n"," ");
    // 解密32字节密文
    aesDecrypt(keytext, 16, ct2, plain2, 32);  
    // 打印16进制形式的解密后的明文
//    printf("%s",""); 
//    printHex(plain2, 32, "解密密出来的结果："); 
    FILE* fp1 = fopen("ECB解密.txt", "a");
    for(i=0;i<32;i++){
    	printhexin(plain2[i],i);
	}
	fwrite(miwen,sizeof(char),64,fp1);
	fclose(fp1);
    // 因为加密前的数据为可见字符的字符串，打印解密后的明文字符，与加密前明文进行对比
//    printf("output plain text\n");
//    for (i = 0; i < 32; ++i) {
//        printf("%c ", plain2[i]);
//    }
    *ciphertext=ct2;	
}

//字符转换为2进制 
void charToBit(char * msg, int* msgBit) {
	int i,j;
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 8; j++) {
			msgBit[(i + 1) * 8 - j - 1] = (msg[i] >> j) & 1;
		}
	}
} 

//字符转换为2进制，2个字符的 
void charToBit1(char * msg, int* msgBit) {
	int i,j;
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			msgBit[(i + 1) * 8 - j - 1] = (msg[i] >> j) & 1;
		}
	}
} 

//二进制转换为字符 
void BitToChar(int* msgBit, char* msg) {
	int sum = 0;
	int count = 0;
	int i;
	for (i = 0; i < 64; i++) {
		sum = sum * 2 + msgBit[i];
		if (i % 8 == 7) {
			msg[count++] = sum;
			sum = 0;
		}
	}
}

//16进制转换为2进制，针对于128位 
void hextob(char *a,int *b){
	int sum;
	int i;
	for(i=0;i<32;i++){
		switch(a[i]){
    			case '0':b[4*i]=0;
    			       b[4*i+1]=0;
    			       b[4*i+2]=0;
    			       b[4*i+3]=0;
    			       break;
    			case '1':b[4*i]=0;
    			       b[4*i+1]=0;
    			       b[4*i+2]=0;
    			       b[4*i+3]=1;
    			       break;
    			case '2':b[4*i]=0;
    			       b[4*i+1]=0;
    			       b[4*i+2]=1;
    			       b[4*i+3]=0;
    			       break;
    			case '3':b[4*i]=0;
    			       b[4*i+1]=0;
    			       b[4*i+2]=1;
    			       b[4*i+3]=1;
    			       break;
    			case '4':b[4*i]=0;
    			       b[4*i+1]=1;
    			       b[4*i+2]=0;
    			       b[4*i+3]=0;
    			       break;
    			case '5':b[4*i]=0;
    			       b[4*i+1]=1;
    			       b[4*i+2]=0;
    			       b[4*i+3]=1;
    			       break;
				case '6':b[4*i]=0;
    			       b[4*i+1]=1;
    			       b[4*i+2]=1;
    			       b[4*i+3]=0;
    			       break;
    			case '7':b[4*i]=0;
    			       b[4*i+1]=1;
    			       b[4*i+2]=1;
    			       b[4*i+3]=1;
    			       break;
    			case '8':b[4*i]=1;
    			       b[4*i+1]=0;
    			       b[4*i+2]=0;
    			       b[4*i+3]=0;
    			       break;
    			case '9':b[4*i]=1;
    			       b[4*i+1]=0;
    			       b[4*i+2]=0;
    			       b[4*i+3]=1;
    			       break;
    			case 'A':b[4*i]=1;
    			       b[4*i+1]=0;
    			       b[4*i+2]=1;
    			       b[4*i+3]=0;
    			       break;
    			case 'B':b[4*i]=1;
    			       b[4*i+1]=0;
    			       b[4*i+2]=1;
    			       b[4*i+3]=1;
    			       break;   			       
    			case 'C':b[4*i]=1;
    			       b[4*i+1]=1;
    			       b[4*i+2]=0;
    			       b[4*i+3]=0;
    			       break;
    			case 'D':b[4*i]=1;
    			       b[4*i+1]=1;
    			       b[4*i+2]=0;
    			       b[4*i+3]=1;
    			       break;
    			case 'E':b[4*i]=1;
    			       b[4*i+1]=1;
    			       b[4*i+2]=1;
    			       b[4*i+3]=0;
    			       break;
    			case 'F':b[4*i]=1;
    			       b[4*i+1]=1;
    			       b[4*i+2]=1;
    			       b[4*i+3]=1;
    			       break;
    			   }
		
	}
}

void CBC(const char* plaintext, const char* keytext, const char* vitext, char** cipher) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	int i;//循环参数 
	int h;//循环参数 
	int j;//循环参数 
	int p=0;//计数 
	int pp=0;//计数 
	int size=16;//单次加密长度 
	char miwencbc[64];//cbc加密的密文的字符表示 
	char mm[32];//存放字符 
	int aaa[128];//存放异或二进制 
	char vitextt1[8];//初始化向量的前8位 
	char vitextt2[8];//初始化向量的后8位 
	char jiemicbc[64];//解密的明文 
	char pfirst[16];//第一次转换的明文字符形式 
	char pfirst1[8];//第一次转换的明文字符形式前8字节 
	char pfirst2[8];//第一次转换的明文字符形式后8字节 
	int vit1[64];//存放初始化向量的二进制表示前64位 
	int vit2[64];//存放初始化向量的二进制表示后64位 
	int vit[128];//存放初始化向量的二进制表示 
	int plainfirst[128];//第一次转换的明文二进制形式 
	int plainfirst1[64];//第一次转换的明文二进制形式前64位 
	int plainfirst2[64];//第一次转换的明文二进制形式后64位 
	int plaina[128];//异或后的二进制表示 
	int plaina1[64];//异或后的二进制表示前64位 
	int plaina2[64];//异或后的二进制表示后64位 
	char mi1[8];//前16字节解密需要的密文块前8字节 
	char mi2[8];//前16字节解密需要的密文块后8字节 
	char mi3[8];//后16字节解密需要的密文块前8字节 
	char mi4[8];//后16字节解密需要的密文块后8字节 
	int mii1[64];//前16字节解密需要的密文块前64位 
	int mii2[64];//前16字节解密需要的密文块后64位 
	int mii3[64];//后16字节解密需要的密文块前64位 
	int mii4[64];//后16字节解密需要的密文块后64位 
	int mimi[128];//密文解密出来的明文的二进制 
	int uu[128];//寄存128位二进制 
	int ooo[128];//寄存128位二进制 
	int mimimi[128];//密文解密出来的明文的二进制异或 
	char yy[2];//寄存加密的字符 
	int xx[8];//寄存加密的字符的二进制 
	int zz[128];//寄存第一块密文的二进制，与解密异或 
	char zhuan[32];//转换的字节 
	int temp[8];//寄存 
	char tempc[1];//寄存的字符表示 
	int tt; 
	char plainafter[16];//加密一次之后的后面16字节明文 
	char plainafter1[8];//前8字节 
	char plainafter2[8];//后8字节 
    const uint8_t *data = (uint8_t*)plaintext;  
    uint8_t ct2[32] = {0};    //外部申请输出数据内存，用于存放加密后数据
    uint8_t plain2[32] = {0}; //外部申请输出数据内存，用于存放解密后数据
       uint8_t plain3[32] = {0}; //外部申请输出数据内存，用于存放解密后数据
//加密16字节明文
//先将初始化向量转换，因为沿用的DES的函数，是64位的转换，所以16个字节转换为两个8字节的数组，分别转换在合成。 

    for(i=0;i<8;i++){
    	vitextt1[i]=vitext[i];
	}
	for(i=0;i<8;i++){
    	vitextt2[i]=vitext[i+8];	
	}
    charToBit(vitextt1,vit1);//转换前64位 
    charToBit(vitextt2,vit2);//转换后64位 
    for(i=0;i<64;i++){
    	vit[i]=vit1[i];
    	vit[i+64]=vit2[i];
	}
	
//转换明文到二进制 ，方法同转换初始化向量 
    for(i=0;i<8;i++){
    	pfirst1[i]=plaintext[i];
    	pfirst2[i]=plaintext[i+8];
	}
	charToBit(pfirst1,plainfirst1);//字符转二进制 
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//异或 
	for(i=0;i<128;i++){
		if(vit[i]==plainfirst[i]){
			plaina[i]=0;
		}
		else{
			plaina[i]=1;
		}
	}
	for(i=0;i<64;i++){
		plaina1[i]=plaina[i];
		plaina2[i]=plaina[i+64];
	}
	//二进制转字符 
	BitToChar(plaina1,plainafter1);
	BitToChar(plaina2,plainafter2);
	for(i=0;i<8;i++){
		plainafter[i]=plainafter1[i];
		plainafter[i+8]=plainafter2[i];
	}
    uint8_t dataa[16];   
    //加密 
    aesEncrypt(keytext, 16, plainafter, ct2, 16); 
    for(i=0;i<32;i++){
    	printhexin(ct2[i],i);
	}
    for(i=0;i<32;i++){
    	miwencbc[p]=miwen[i];//赋值密文 
    	zhuan[i]=miwencbc[p];
    	p++;    	
	}
	hextob(zhuan,zz);//16进制转换二进制 
    // 解密16字节密文
    aesDecrypt(keytext, 16, ct2, plain2, 16);  
    for(i=0;i<8;i++){
    	mi1[i]=plain2[i];
    	mi2[i]=plain2[i+8];
	}
	charToBit(mi1,mii1);
	charToBit(mi2,mii2);
	for(i=0;i<64;i++){
		mimi[i]=mii1[i];
		mimi[i+64]=mii2[i];
	}
	//异或 
	for(i=0;i<128;i++){
		if(mimi[i]==vit[i]){
			mimimi[i]=0;
		}
		else{
			mimimi[i]=1;
		}
	}
    for(i=0;i<16;i++){
    	for(j=0;j<8;j++){
    		xx[j]=mimimi[8*i+j];
		}
		b1(xx,yy);
		jiemicbc[2*i]=yy[0];
		jiemicbc[2*i+1]=yy[1];
	}
	//16进制转换二进制 
	hextob(miwencbc,aaa);
    for(i=0;i<8;i++){
    	pfirst1[i]=plaintext[i+16];
    	pfirst2[i]=plaintext[i+24];
	}
	charToBit(pfirst1,plainfirst1);
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//异或 
	for(i=0;i<128;i++){
		if(aaa[i]==plainfirst[i]){
			plaina[i]=0;
		}
		else{
			plaina[i]=1;
		}
	}
	for(i=0;i<64;i++){
		plaina1[i]=plaina[i];
		plaina2[i]=plaina[i+64];
	}
	BitToChar(plaina1,plainafter1);
	BitToChar(plaina2,plainafter2);
	for(i=0;i<8;i++){
		plainafter[i]=plainafter1[i];
		plainafter[i+8]=plainafter2[i];
	}
	//第二次加密 
     aesEncrypt(keytext, 16, plainafter, ct2, 16); 
    for(i=0;i<32;i++){
    	printhexin(ct2[i],i);
	}
    for(i=0;i<32;i++){
    	miwencbc[p]=miwen[i];
    	p++;
	}
    // 第二次解密16字节密文
    aesDecrypt(keytext, 16, ct2, plain3, 16);  
     for(i=0;i<8;i++){
    	mi3[i]=plain3[i];
    	mi4[i]=plain3[i+8];
	}
	charToBit(mi3,mii3);
	charToBit(mi4,mii4);
	for(i=0;i<64;i++){
		uu[i]=mii3[i];
		uu[i+64]=mii4[i];
	}

	for(i=0;i<128;i++){
		if(uu[i]==zz[i]){
			ooo[i]=0;
		}
		else{
			ooo[i]=1;
		}
	}	
    for(i=0;i<16;i++){
    	for(j=0;j<8;j++){
    		xx[j]=ooo[8*i+j];
		}
		b1(xx,yy);
		jiemicbc[2*i+32]=yy[0];
		jiemicbc[2*i+1+32]=yy[1];
	}
//    printf("%s", "加密出来的结果是：");    
//	for(i=0;i<64;i++){
//		printf("%c",miwencbc[i]);
//	}
//	printf("%s\n","");
//	printf("%s","解密出来的结果是：");
//	for(i=0;i<64;i++){
//		printf("%c",jiemicbc[i]);	
//	}
    FILE* fp = fopen(cipherfile, "a");
    fwrite(miwencbc,sizeof(char),64,fp);
	fclose(fp);
	FILE* fp1 = fopen("CBC解密.txt", "a");
	fwrite(jiemicbc,sizeof(char),64,fp1);
	fclose(fp1);
    ciphertext=ct2;
}

//十进制转换二进制 
dtob(int a,int *b,int c){
	int i;
	int sum;
	for(i=0;i<8;i++){
		b[7+8*c-i]=a%2;
		a=a/2;
	}
}

//二进制转换字符，仅限于8位二进制转换2位16进制，由于是DES的函数，只能适用于此。 
int b1(int bit[8],char ch[2]){
    	int i;
    	int sum=0;
    	for(i=0;i<2;i++){
    		sum=2*2*2*(int)bit[4*i]+2*2*(int)bit[4*i+1]+2*(int)bit[4*i+2]+(int)bit[4*i+3];
    		switch(sum){
    			case 0:ch[i]='0';
    			       break;
    			case 1:ch[i]='1'; 
    			       break;
    			case 2:ch[i]='2';
    			       break;
    			case 3:ch[i]='3';
    			       break;
    			case 4:ch[i]='4';
    			       break;
    			case 5:ch[i]='5';
    			       break;
				case 6:ch[i]='6';
    			       break;
    			case 7:ch[i]='7';
    			       break;
    			case 8:ch[i]='8';
    			       break;
    			case 9:ch[i]='9';
    			       break;
    			case 10:ch[i]='A';
    			       break;
    			case 11:ch[i]='B';
    			       break;    			       
    			case 12:ch[i]='C';
    			       break;
    			case 13:ch[i]='D';
    			       break;
    			case 14:ch[i]='E';
    			       break;
    			case 15:ch[i]='F';
    			       break;    			       
			}
			sum=0;
		}
	}

void CFB(const char* plaintext, const char* keytext, const char* vitext, char** cipher) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	 int i;//循环变量 
	 int h;//循环变量 
	 int tem[128];//寄存ct2的二进制，进行异或处理 
	char pfirst[16];//16字节明文 
	char pfirst1[8];//16字节明文的前8字节 
	char pfirst2[8];//16字节明文的后8字节 
	int plainfirst[128];//16字节明文的二进制表示 
	int plainfirst1[64];//16字节明文的二进制表示的前64位 
	int plainfirst2[64];//16字节明文的二进制表示 后64位 
	int change[128];//交换的寄存，便于更新v向量 
	int out[128];//异或结果 
	int oo[8];//异或结果 
	char q[2];//寄存异或出来加密出来的密文 
	int vitext1[64];//初始化向量的前64位 
	int vitext2[64];//初始化向量的后64位 
	char vitextchar1[8];//初始化向量的前8字节 
	char vitextchar2[8];//初始化向量的8字节 
	int vitextbit[128];//初始化的2进制 
	int w1[64];//寄存 
	int w2[64];//寄存 
	char jiemi[64];//解密出来的明文 
	char mimi1[16];//存放加密后的密文的前16字节 
	char mimi2[16];//存放加密后的密文的后16字节 
	int mimimi1[128];//存放加密后的密文的前128位 
	int mimimi2[128];//存放加密后的密文的后128位 
	char aes[16];//解密的寄存 
	char vitt[16];//加密的寄存 
    const uint8_t *data = (uint8_t*)plaintext;  
    uint8_t ct2[32] = {0};    //外部申请输出数据内存，用于存放加密后数据
    uint8_t plain2[32] = {0}; //外部申请输出数据内存，用于存放解密后数据

//寄存加密和解密的初始化向量 
    for(i=0;i<16;i++){
 	    vitt[i]=vitext[i];
    }    
    for(i=0;i<16;i++){
    	aes[i]=vitext[i];
	}
	//加密初始化向量的处理，将字节转换为二进制 
    for(i=0;i<8;i++){
    	vitextchar1[i]=vitext[i];
    	vitextchar2[i]=vitext[i+8];
	}
	//字节转换二进制 
	charToBit(vitextchar1,w1);
	charToBit(vitextchar2,w2); 
	for(i=0;i<64;i++){
		vitextbit[i]=w1[i];
		vitextbit[i+64]=w2[i];
	}
	//加密的明文的赋值 
	for(i=0;i<8;i++){
  		pfirst1[i]=plaintext[i];
 	   	pfirst2[i]=plaintext[i+8];
	}
	//字节转换二进制 
	charToBit(pfirst1,plainfirst1);
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//加密 
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, vitt, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);
   		}
   		//异或 
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
		//异或出来的结果转换字符 
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		miwen[2*h+i]=q[i];
		}
		//更新v向量 
		for(i=0;i<128;i++){
			change[i]=vitextbit[i];
		}
		for(i=0;i<120;i++){
			vitextbit[i]=change[i+8];
		}
		for(i=0;i<8;i++){
		   vitextbit[120+i]=out[i];
		}
		for(i=0;i<64;i++){
			vitext1[i]=vitextbit[i];
			vitext2[i]=vitextbit[i+64];
		}
		//二进制转换为字节 
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);	
		//更新初始化向量 
		for(i=0;i<8;i++){
			vitt[i]=vitextchar1[i];
			vitt[i+8]=vitextchar2[i];
		}
    }
    //处理后面16字节的明文 
    for(i=0;i<8;i++){
  		pfirst1[i]=plaintext[i+16];
 	   	pfirst2[i]=plaintext[i+24];
	}
	//字节转换二进制 
	charToBit(pfirst1,plainfirst1);
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//加密 
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, vitt, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);//十进制转换二进制 
   		}
   		//异或 
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		miwen[2*h+i+32]=q[i];
		}
		for(i=0;i<128;i++){
			change[i]=vitextbit[i];
		}
		for(i=0;i<120;i++){
			vitextbit[i]=change[i+8];
		}
		for(i=0;i<8;i++){
		   vitextbit[120+i]=out[i];
		}
		for(i=0;i<64;i++){
			vitext1[i]=vitextbit[i];
			vitext2[i]=vitextbit[i+64];
		}
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);
		
		for(i=0;i<8;i++){
			vitt[i]=vitextchar1[i];
			vitt[i+8]=vitextchar2[i];
		}
    }
//    printf("加密后的密文：\n");
//    for (i = 0; i < 64; ++i) {
//        printf("%c", miwen[i]);
//    }
//    printf("\n解密后的明文：\n");	
    //解密第一轮 （16字节）
	//重新更新初始化向量 
    for(i=0;i<8;i++){
    	vitextchar1[i]=aes[i];
    	vitextchar2[i]=aes[i+8];
	}
	charToBit(vitextchar1,w1);
	charToBit(vitextchar2,w2); 
	for(i=0;i<64;i++){
		vitextbit[i]=w1[i];
		vitextbit[i+64]=w2[i];
	}
//加载密文 
    for(i=0;i<32;i++){
  		mimi1[i]=miwen[i];
	}
    hextob(mimi1,mimimi1);//16进制转换2进制 
	for(i=0;i<128;i++){
		plainfirst[i]=mimimi1[i];
	}
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, aes, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);//十进制转换二进制 
   		}
   		//异或 
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
		//得出结果 
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	//赋值解密 
  	  	for(i=0;i<2;i++){
    		jiemi[2*h+i]=q[i];
		}
		//更新初始化向量 
		for(i=0;i<128;i++){
			change[i]=vitextbit[i];
		}
		for(i=0;i<120;i++){
			vitextbit[i]=change[i+8];
		}
		for(i=0;i<8;i++){
		   vitextbit[120+i]=plainfirst[i+8*h];
		}
		for(i=0;i<64;i++){
			vitext1[i]=vitextbit[i];
			vitext2[i]=vitextbit[i+64];
		}
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);	
		for(i=0;i<8;i++){
			aes[i]=vitextchar1[i];
			aes[i+8]=vitextchar2[i];
		}

    }
//    for (i = 0; i < 32; ++i) {
//        printf("%c", jiemi[i]);
//    }
    FILE* fp = fopen("CFB解密.txt","a");
	fwrite(jiemi,sizeof(char),32,fp);
	fclose(fp);
    //解密第二段 后16字节 
    for(i=0;i<32;i++){
  		mimi1[i]=miwen[i+32];
	}
    hextob(mimi1,mimimi1);//16进制转换二进制 
	for(i=0;i<128;i++){
		plainfirst[i]=mimimi1[i];
	}
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, aes, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);//十进制转换二进制 
   		}
   		//异或 
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
		//输出结果到啊jiemi【64】 
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		jiemi[2*h+32+i]=q[i];
		}
		//更新初始化向量 
		for(i=0;i<128;i++){
			change[i]=vitextbit[i];
		}
		for(i=0;i<120;i++){
			vitextbit[i]=change[i+8];
		}
		for(i=0;i<8;i++){
		   vitextbit[120+i]=plainfirst[i+8*h];
		}
		for(i=0;i<64;i++){
			vitext1[i]=vitextbit[i];
			vitext2[i]=vitextbit[i+64];
		}
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);	
		for(i=0;i<8;i++){
			aes[i]=vitextchar1[i];
			aes[i+8]=vitextchar2[i];
		}
    }
 //   for (i =32; i < 64; ++i) {
//        printf("%c", jiemi[i]);
 //   }
    FILE* fp1 = fopen(cipherfile, "a");
	fwrite(miwen,sizeof(char),64,fp1);
	fclose(fp1);
	FILE* fp2 = fopen("CFB解密.txt", "a");
	fwrite(&jiemi[32],sizeof(char),32,fp2);
	fclose(fp2);
    // 因为加密前的数据为可见字符的字符串，打印解密后的明文字符，与加密前明文进行对比
   
    ciphertext=ct2;
	
}

//OFB的变量意义同上CFB ，中间函数类似CFB，所以不进行详细注释
 
void OFB(const char* plaintext, const char* keytext, const char* vitext, char** cipher) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	int i;
	 int h;
	 int tem[128];
	char pfirst[16];
	char pfirst1[8];
	char pfirst2[8];
	int plainfirst[128];
	int plainfirst1[64];
	int plainfirst2[64];
	int change[128];
	int out[128];
	int oo[8];
	char q[2];
	int vitext1[64];
	int vitext2[64];
	char vitextchar1[8];
	char vitextchar2[8];
	int vitextbit[128];
	int w1[64];
	int w2[64];
	char jiemi[64];
	char mimi[32];
	int mimimi[128];
    const uint8_t *data = (uint8_t*)plaintext;  
    uint8_t ct2[32] = {0};    //外部申请输出数据内存，用于存放加密后数据
    uint8_t plain2[32] = {0}; //外部申请输出数据内存，用于存放解密后数据
    //加密32字节明文
    char vitt[16];
    char jie[16];
    for(i=0;i<16;i++){
    	vitt[i]=vitext[i];
    	jie[i]=vitext[i];
	}
	//初始化向量的处理 
    for(i=0;i<8;i++){
    	vitextchar1[i]=vitext[i];
    	vitextchar2[i]=vitext[i+8];
	}
	charToBit(vitextchar1,w1);
	charToBit(vitextchar2,w2); 
	for(i=0;i<64;i++){
		vitextbit[i]=w1[i];
		vitextbit[i+64]=w2[i];
	}
	//明文赋值 
	for(i=0;i<8;i++){
  		  	pfirst1[i]=plaintext[i];
 		   	pfirst2[i]=plaintext[i+8];
	}
	charToBit(pfirst1,plainfirst1);
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//加密16字节 
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, vitt, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);
   		}
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		miwen[2*h+i]=q[i];
		}
		for(i=0;i<128;i++){
			change[i]=vitextbit[i];
		}
		for(i=0;i<120;i++){
			vitextbit[i]=change[i+8];
		}
		for(i=0;i<8;i++){
		   vitextbit[120+i]=tem[i];
		}
		for(i=0;i<64;i++){
			vitext1[i]=vitextbit[i];
			vitext2[i]=vitextbit[i+64];
		}
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);	
		for(i=0;i<8;i++){
			vitt[i]=vitextchar1[i];
			vitt[i+8]=vitextchar2[i];
		}
    }
    //明文的更新 
    for(i=0;i<8;i++){
  		  	pfirst1[i]=plaintext[i+16];
 		   	pfirst2[i]=plaintext[i+24];
	}
	charToBit(pfirst1,plainfirst1);
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//加密后16字节 
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, vitt, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);
   		}
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		miwen[2*h+i+32]=q[i];
		}
		for(i=0;i<128;i++){
			change[i]=vitextbit[i];
		}
		for(i=0;i<120;i++){
			vitextbit[i]=change[i+8];
		}
		for(i=0;i<8;i++){
		   vitextbit[120+i]=tem[i];
		}
		for(i=0;i<64;i++){
			vitext1[i]=vitextbit[i];
			vitext2[i]=vitextbit[i+64];
		}
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);		
		for(i=0;i<8;i++){
			vitt[i]=vitextchar1[i];
			vitt[i+8]=vitextchar2[i];
		}
    }
	//初始化向量的最初始化 
    for(i=0;i<8;i++){
    	vitextchar1[i]=vitext[i];
    	vitextchar2[i]=vitext[i+8];
	}
	charToBit(vitextchar1,w1);
	charToBit(vitextchar2,w2); 
	for(i=0;i<64;i++){
		vitextbit[i]=w1[i];
		vitextbit[i+64]=w2[i];
	}
	//密文的更新 
	for(i=0;i<32;i++){
		mimi[i]=miwen[i];
	}
	hextob(mimi,mimimi);
	for(i=0;i<128;i++){
		plainfirst[i]=mimimi[i];
	}
	//解密前16字节 
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, jie, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);
   		}
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		jiemi[2*h+i]=q[i];
		}
		for(i=0;i<128;i++){
			change[i]=vitextbit[i];
		}
		for(i=0;i<120;i++){
			vitextbit[i]=change[i+8];
		}
		for(i=0;i<8;i++){
		   vitextbit[120+i]=tem[i];
		}
		for(i=0;i<64;i++){
			vitext1[i]=vitextbit[i];
			vitext2[i]=vitextbit[i+64];
		}
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);	
		for(i=0;i<8;i++){
			jie[i]=vitextchar1[i];
			jie[i+8]=vitextchar2[i];
		}
    }
    //密文的更新 
    for(i=0;i<32;i++){
  		  	mimi[i]=miwen[i+32];
	}
    hextob(mimi,mimimi);
	for(i=0;i<128;i++){
		plainfirst[i]=mimimi[i];
	}
	//解密后16字节 
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, jie, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);
   		}
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		jiemi[2*h+i+32]=q[i];
		}
		for(i=0;i<128;i++){
			change[i]=vitextbit[i];
		}
		for(i=0;i<120;i++){
			vitextbit[i]=change[i+8];
		}
		for(i=0;i<8;i++){
		   vitextbit[120+i]=tem[i];
		}
		for(i=0;i<64;i++){
			vitext1[i]=vitextbit[i];
			vitext2[i]=vitextbit[i+64];
		}
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);		
		for(i=0;i<8;i++){
			jie[i]=vitextchar1[i];
			jie[i+8]=vitextchar2[i];
		}
    } 
    FILE* fp = fopen(cipherfile, "a");
	fwrite(miwen,sizeof(char),64,fp);
	fclose(fp);
////	printf("%s\n"," ");
    FILE* fp1 = fopen("OFB解密.txt", "a");
	fwrite(jiemi,sizeof(char),64,fp1);
	fclose(fp1);
    // 因为加密前的数据为可见字符的字符串，打印解密后的明文字符，与加密前明文进行对比
 //   printf("加密后的密文：\n");
 //   for (i = 0; i < 64; ++i) {
 //       printf("%c", miwen[i]);
 //   }
 //   printf("%s\n"," ");
  //   printf("解密后的明文：\n");
 //   for (i = 0; i < 64; ++i) {
 //       printf("%c", jiemi[i]);
 //   }
    ciphertext=ct2;
}

int main(int argc, char** argv) {
	int i;
	char p[16];
	int starttime;
	int endtime;
	float v;	 
	//argc 表示参数的个数，argv表示每个参数的一个字符串数组
	printf("argc:%d\n", argc);
	for (i = 0; i < argc; i++) {
		printf("%d : %s\n", i, argv[i]);
	}

	/*
	-p plainfile 指定明文文件的位置和名称
	-k keyfile  指定密钥文件的位置和名称
	-v vifile  指定初始化向量文件的位置和名称
	-m mode  指定加密的操作模式
	-c cipherfile 指定密文文件的位置和名称。
	*/

	if (argc % 2 == 0) {
		print_usage();
	}

	for (i = 1; i < argc; i += 2) {
		if (strlen(argv[i]) != 2) {
			print_usage();
		}
		switch (argv[i][1]) {
		case 'p':
			plainfile = argv[i + 1];
			break;
		case 'k':
			keyfile = argv[i + 1];
			break;
		case 'v':
			vifile = argv[i + 1];
			break;
		case 'm':
			if (strcmp(argv[i + 1], DES_MODE[0]) != 0 && strcmp(argv[i + 1], DES_MODE[1]) != 0 && strcmp(argv[i + 1], DES_MODE[2]) != 0 && strcmp(argv[i + 1], DES_MODE[3]) != 0) {
				print_usage();
			}
			mode = argv[i + 1];
			break;
		case 'c':
			cipherfile = argv[i + 1];
			break;
		default:
			print_usage();
		}
	}

	if (plainfile == NULL || keyfile == NULL || mode == NULL || cipherfile == NULL) {
		print_usage();
	}

	if (strcmp(mode, "ECB") != 0 && vifile == NULL) {
		print_usage();
	}

	printf("解析参数完成！\n");
	printf("参数为明文文件的位置和名称:%s\n", plainfile);
	printf("参数为密钥文件的位置和名称:%s\n", keyfile);
	if (strcmp(mode, "ECB") != 0) {
		printf("参数为初始化向量文件文件的位置和名称:%s\n", vifile);
	}
	printf("参数为密文文件的位置和名称:%s\n", cipherfile);
	printf("参数为加密的模式:%s\n", mode);

	printf("现在开始读取文件！\n");

	printf("读取明文文件...\n");
	bool read_result = readfile2memory(plainfile, &plaintext);
	if (read_result == false) {
		printf("读取明文文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取明文文件成功！\n");

	printf("读取密钥文件...\n");
	read_result = readfile2memory(keyfile, &keytext);
	if (read_result == false) {
		printf("读取密钥文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取密钥文件成功！\n");

	if (strcmp(mode, "ECB") != 0) {
		printf("读取初始向量文件...\n");
		read_result = readfile2memory(vifile, &vitext);
		if (read_result == false) {
			printf("读取初始向量文件失败，请检查路径及文件是否存在\n");
			exit(-1);
		}
		printf("读取初始向量文件成功！\n");
	}

	if (strcmp(mode, "ECB") == 0) {
		starttime=clock();
		for(i=0;i<81920;i++){
			ECB(&plaintext[32*i], keytext, &ciphertext);
		}		
		endtime=clock();
//		v=(float)(5*1000/(endtime-starttime));
		printf("\n运行了%d毫秒\n",endtime-starttime);
//		printf("加解密速度为：%f Bytes/ms",v);
	}
	else if (strcmp(mode, "CBC") == 0) {
		starttime=clock();	
		for(i=0;i<81920;i++){
		    CBC(&plaintext[32*i], keytext, vitext, &ciphertext);			
		} 
        endtime=clock();
		printf("\n运行了%d毫秒\n",endtime-starttime); 	
	}
	else if (strcmp(mode, "CFB") == 0) {
		starttime=clock();
		for(i=0;i<81920;i++){
			CFB(&plaintext[32*i], keytext, vitext, &ciphertext);
		}
		endtime=clock();
		printf("\n运行了%d毫秒\n",endtime-starttime); 
	}
	else if (strcmp(mode, "OFB") == 0) {
		starttime=clock();
		for(i=0;i<81920;i++){
		    OFB(&plaintext[32*i], keytext, vitext, &ciphertext);
	    }
	    endtime=clock();
		printf("\n运行了%d毫秒\n",endtime-starttime); 
	}
	else {
		//不应该能到达这里
		printf("致命错误！！！\n");
		exit(-2);
	}
	if (ciphertext == NULL) {
		printf("同学，ciphertext没有分配内存哦，需要补补基础~\n失败，程序退出中...");
		exit(-1);
	}
	int count = strlen(ciphertext);
	char* cipherhex = malloc(count * 2 + 1);
	memset(cipherhex, 0, count * 2 + 1);
	printf("%s\n写入文件中...\n", cipherhex);
	printf("恭喜你完成了该程序，请提交代码!");
	return 0;
}
