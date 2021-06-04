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
#define BLOCKSIZE 16  //AES-128���鳤��Ϊ16�ֽ�

// uint8_t y[4] -> uint32_t x
#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

// uint32_t x -> uint8_t y[4]
#define STORE32H(x, y) \
  do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
       (y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

// ��uint32_t x����ȡ�ӵ�λ��ʼ�ĵ�n���ֽ�
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
// �ֽ��滻Ȼ��ѭ������1λ
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                ((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

// uint32_t xѭ������nλ
#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))
// uint32_t xѭ������nλ
#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))

const char* DES_MODE[] = { "ECB","CBC","CFB","OFB" };
char* plainfile = NULL;//�����ļ� 
char* keyfile = NULL;//��Կ�ļ� 
char* vifile = NULL;//��ʼ�������ļ� 
char* mode = NULL;//ģʽ 
char* cipherfile = NULL;//�����ļ� 
char* plaintext = NULL;//���� 
char* keytext = NULL;//��Կ 
char* vitext = NULL;//��ʼ������ 
char* ciphertext = NULL;//���� 
char miwen[64];//���ܳ��������ĵ�char 
char jiemimingwen[64];//���ܳ��������ĵ�char 
void hextochar(int a,const b,int c);//16����ת�����ַ� 
void charToBit(char * msg, int* msgBit);//�����ֽڵ�ת�������� 
void charToBit1(char * msg, int* msgBit);//�����ֽڵ�ת�������� 
////char vitextchange[16];
int b1(int bit[8],char ch[2]);	
typedef struct{
    uint32_t eK[44], dK[44];    // encKey, decKey
    int Nr; // 10 rounds
}AesKey;

// AES-128�ֳ���
static const uint32_t rcon[10] = {
        0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL,
        0x20000000UL, 0x40000000UL, 0x80000000UL, 0x1B000000UL, 0x36000000UL
};
// AES��S��
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

//AES����S��
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

// �������16����ת����4*4�ľ�����ʽ 
int loadStateArray(uint8_t (*state)[4], const uint8_t *in) {
	int i,j; 
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[j][i] = *in++;   //������ʽ�ĸ�ֵ 
        }
    }
    return 0;
}

// �������4*4�ľ�����ʽת����16������ʽ 
int storeStateArray(uint8_t (*state)[4], uint8_t *out) {
	int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            *out++ = state[j][i]; 
        }
    }
    return 0;
}

//��Կ��չ
int keyExpansion(const uint8_t *key, uint32_t keyLen, AesKey *aesKey) {
    int i,j;
    if (NULL == key || NULL == aesKey){
        printf("��Կ��չʧ��\n");
        return -1;
    }
    if (keyLen != 16){
        printf("��Կ���� = %d, ��֧��ת��\n", keyLen);
        return -1;
    }
    uint32_t *w = aesKey->eK;  //������Կ
    uint32_t *v = aesKey->dK;  //������Կ
    /* W[0-3] */
    //0-3����Կ�û� 
    for (i = 0; i < 4; ++i) {
        LOAD32H(w[i], key + 4*i);
    }
    /* W[4-43] */
    //4-43����Կ�û� 
    for (i = 0; i < 10; ++i) {
        w[4] = w[0] ^ MIX(w[3]) ^ rcon[i];
        w[5] = w[1] ^ w[4];
        w[6] = w[2] ^ w[5];
        w[7] = w[3] ^ w[6];
        w += 4;
    }
    w = aesKey->eK+44 - 4;
    //������Կ����Ϊ������Կ����ĵ��򣬷���ʹ�ã���ek��11�����������з����dk��Ϊ������Կ
    //��dk[0-3]=ek[41-44], dk[4-7]=ek[37-40]... dk[41-44]=ek[0-3]
    for (j = 0; j < 11; ++j) {

        for ( i = 0; i < 4; ++i) {
            v[i] = w[i];
        }
        w -= 4;
        v += 4;
    }

    return 0;
}

// ����Կ��
int addRoundKey(uint8_t (*state)[4], const uint32_t *key) {
    uint8_t k[4][4];
    int i,j;
    /* i: ��, j: �� */
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            k[i][j] = (uint8_t) BYTE(key[j], 3 - i);  /* �� uint32 key[4] ��ת��Ϊ���� uint8 k[4][4] */
            state[i][j] ^= k[i][j];
        }
    }
    return 0;
}

//�ֽ��滻
int subBytes(uint8_t (*state)[4]) {
    /* i: ��, j: �� */
    int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = S[state[i][j]]; //ֱ��ʹ��ԭʼ�ֽ���ΪS�������±�
        }
    }
    return 0;
}

//���ֽ��滻
int invSubBytes(uint8_t (*state)[4]) {
    /* i: ��, j: c�� */
    int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = inv_S[state[i][j]];//ֱ��ʹ��ԭʼ�ֽ���ΪS�������±�
        }
    }
    return 0;
}

//����λ
int shiftRows(uint8_t (*state)[4]) {
    uint32_t block[4] = {0};
    int i;
    /* i: row */
    for (i = 0; i < 4; ++i) {
    //������ѭ����λ���Ȱ�һ��4�ֽ�ƴ��uint_32�ṹ����λ����ת�ɶ�����4���ֽ�uint8_t
        LOAD32H(block[i], state[i]);
        block[i] = ROF32(block[i], 8*i);
        STORE32H(block[i], state[i]);
    }

    return 0;
}

//������λ
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

// ���ֽڵ�٤�޻���˷�����
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

// �л��
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
        for (j = 0; j < 4; ++j) {  //٤�޻���ӷ��ͳ˷�
            state[i][j] = GMul(M[i][0], tmp[0][j]) ^ GMul(M[i][1], tmp[1][j])
                        ^ GMul(M[i][2], tmp[2][j]) ^ GMul(M[i][3], tmp[3][j]);
        }
    }

    return 0;
}

// ���л��
int invMixColumns(uint8_t (*state)[4]) {
    uint8_t tmp[4][4];
    int i,j;
    uint8_t M[4][4] = {{0x0E, 0x0B, 0x0D, 0x09},
                       {0x09, 0x0E, 0x0B, 0x0D},
                       {0x0D, 0x09, 0x0E, 0x0B},
                       {0x0B, 0x0D, 0x09, 0x0E}};  //ʹ���л�Ͼ���������

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

// AES-128���ܺ���������keyӦΪ16�ֽڳ��ȣ����볤��Ӧ����16�ֽ���������pt�������ģ�ct���������ʮ���Ƶı�ʾ��len�Ǽ��ܵĳ��� 
int aesEncrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *pt, uint8_t *ct, uint32_t len) {
    AesKey aesKey;
    uint8_t *pos = ct;
    const uint32_t *rk = aesKey.eK;  //������Կָ��
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    int i,j;
    if (NULL == key || NULL == pt || NULL == ct){
        printf("��������\n");
        return -1;
    }

    if (keyLen > 16){
        printf("��Կ�ĳ���һ��Ҫ��16λŶ��\n");
        return -1;
    }

    if (len % BLOCKSIZE){
        printf("������ַ����Ȳ���Ŷ��\n");
        return -1;
    }

    memcpy(actualKey, key, keyLen);
    keyExpansion(actualKey, 16, &aesKey);  // ��Կ��չ

	// ʹ��ECBģʽѭ�����ܶ�����鳤�ȵ�����
    for (i = 0; i < len; i += BLOCKSIZE) {
		// ��16�ֽڵ�����ת��Ϊ4x4״̬���������д���
        loadStateArray(state, pt);
        // ����Կ��
        addRoundKey(state, rk);

        for (j = 1; j < 10; ++j) {
            rk += 4;
            subBytes(state);   // �ֽ��滻
            shiftRows(state);  // ����λ
            mixColumns(state); // �л��
            addRoundKey(state, rk); // ����Կ��
        }

        subBytes(state);    // �ֽ��滻
        shiftRows(state);  // ����λ
        // �˴��������л��
        addRoundKey(state, rk+4); // ����Կ��
		
		// ��4x4״̬����ת��Ϊuint8_tһά�����������
        storeStateArray(state, pos);

        pos += BLOCKSIZE;  // ���������ڴ�ָ���ƶ�����һ������
        pt += BLOCKSIZE;   // ��������ָ���ƶ�����һ������
        rk = aesKey.eK;    // �ָ�rkָ�뵽��Կ��ʼλ��
    }
    return 0;
}

// AES128���ܣ� ����Ҫ��ͬ����
int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len) {
    AesKey aesKey;
    uint8_t *pos = pt;
    const uint32_t *rk = aesKey.dK;  //������Կָ��
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    int i,j;
    if (NULL == key || NULL == ct || NULL == pt){
        printf("�����������\n");
        return -1;
    }

    if (keyLen > 16){
        printf("��Կ����һ��Ҫ��16Ŷ��\n");
        return -1;
    }

    if (len % BLOCKSIZE){
        printf("����ĳ��Ȳ���Ŷ��\n");
        return -1;
    }

    memcpy(actualKey, key, keyLen);
    keyExpansion(actualKey, 16, &aesKey);  //��Կ��չ��ͬ����

    for (i = 0; i < len; i += BLOCKSIZE) {
        // ��16�ֽڵ�����ת��Ϊ4x4״̬���������д���
        loadStateArray(state, ct);
        // ����Կ�ӣ�ͬ����
        addRoundKey(state, rk);

        for (j = 1; j < 10; ++j) {
            rk += 4;
            invShiftRows(state);    // ������λ
            invSubBytes(state);     // ���ֽ��滻��������˳����Եߵ�
            addRoundKey(state, rk); // ����Կ�ӣ�ͬ����
            invMixColumns(state);   // ���л��
        }

        invSubBytes(state);   // ���ֽ��滻
        invShiftRows(state);  // ������λ
        // �˴�û�����л��
        addRoundKey(state, rk+4);  // ����Կ�ӣ�ͬ����

        storeStateArray(state, pos);  // ������������
        pos += BLOCKSIZE;  // ��������ڴ�ָ����λ���鳤��
        ct += BLOCKSIZE;   // ���������ڴ�ָ����λ���鳤��
        rk = aesKey.dK;    // �ָ�rkָ�뵽��Կ��ʼλ��
    }
    return 0;
}

//���16���� 
void printHex(const uint8_t *ptr, int len, char *tag) {
	int i;
    printf("%s\ndata[%d]: ", tag, len);
    for (i = 0; i < len; ++i) {
        printf("%.2X ", *ptr++);
    }
    printf("\n");
}

//���16���� 
void printhexin(int d,int i){
	int n,a1,count=0,j;//count ���ڽǱ�ļ�����j ���� for ѭ�� 
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

//16����ת��Ϊ2���ƣ�c��λ�� 
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
	printf("\n�Ƿ�����,֧�ֵĲ��������£�\n-p plainfile ָ�������ļ���λ�ú�����\n-k keyfile  ָ����Կ�ļ���λ�ú�����\n-v vifile  ָ����ʼ�������ļ���λ�ú�����\n-m mode  ָ�����ܵĲ���ģʽ(ECB,CBC,CFB,OFB)\n-c cipherfile ָ�������ļ���λ�ú����ơ�\n");
	exit(-1);
}

bool readfile2memory(const char* filename, char** memory) {
	FILE* fp = NULL;
	int i; 
	fp = fopen(filename, "r");//���ļ� 
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END);//�����ļ�ָ��λ�� 
	int size = ftell(fp);//�õ��ļ�λ��ָ�뵱ǰλ��������ļ��׵�ƫ���ֽ���
	fseek(fp, 0, SEEK_SET);
	if (size % 2 != 0) {
		printf("%s:�ļ��ֽ�����Ϊż����\n", filename);
		fclose(fp);
		return false;
	}
	char* tmp = malloc(size);//�����ڴ� 
	memset(tmp, 0, size);//��tmp���� 
	fread(tmp, size, 1, fp);
	if (ferror(fp)) {
		printf("��ȡ%s�����ˣ�\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}
	*memory = malloc(size / 2 + 1);
	memset(*memory, 0, size / 2 + 1);//��memory�����ڴ� 
	char parsewalker[3] = { 0 };
	for (i = 0; i < size; i += 2) {
		parsewalker[0] = tmp[i];
		parsewalker[1] = tmp[i + 1];
		(*memory)[i / 2] = strtol(parsewalker, 0, 16);//ɨ������ַ���������ǰ��Ŀո��ַ���ֱ���������ֻ��������Ųſ�ʼ��ת���������������ֻ��ַ�������ʱ('\0')����ת��������������ء� 
//		printf("debug info : %c\n", (*memory)[i / 2]);
	}

	free(tmp);

	return true;
}

void ECB(const char* plaintext, const char* keytext, char** ciphertext) {
	//plaintextΪ�����ַ�����,��NULL��β
	//keytextΪ��Կ�ַ����飬��NULL��β
	//cipherΪ�����ַ����飬��NULL��β����Ҫ������䣬ע��Ҫ�ocipher����ռ䣡
	//��ʵ��~
    int i;
    const uint8_t *data = (uint8_t*)plaintext;  
    uint8_t ct2[32] = {0};    //�ⲿ������������ڴ棬���ڴ�ż��ܺ�����
    uint8_t plain2[32] = {0}; //�ⲿ������������ڴ棬���ڴ�Ž��ܺ�����
    //����32�ֽ�����
    aesEncrypt(keytext, 16, data, ct2, 32); //���� 
//    printHex(ct2, 32, "���ܳ����Ľ����");//��ӡ16���� 
    FILE* fp = fopen(cipherfile, "a");
    for(i=0;i<32;i++){
    	printhexin(ct2[i],i);
	}
	fwrite(miwen,sizeof(char),64,fp);
	fclose(fp);
///	printf("%s\n"," ");
    // ����32�ֽ�����
    aesDecrypt(keytext, 16, ct2, plain2, 32);  
    // ��ӡ16������ʽ�Ľ��ܺ������
//    printf("%s",""); 
//    printHex(plain2, 32, "�����ܳ����Ľ����"); 
    FILE* fp1 = fopen("ECB����.txt", "a");
    for(i=0;i<32;i++){
    	printhexin(plain2[i],i);
	}
	fwrite(miwen,sizeof(char),64,fp1);
	fclose(fp1);
    // ��Ϊ����ǰ������Ϊ�ɼ��ַ����ַ�������ӡ���ܺ�������ַ��������ǰ���Ľ��жԱ�
//    printf("output plain text\n");
//    for (i = 0; i < 32; ++i) {
//        printf("%c ", plain2[i]);
//    }
    *ciphertext=ct2;	
}

//�ַ�ת��Ϊ2���� 
void charToBit(char * msg, int* msgBit) {
	int i,j;
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 8; j++) {
			msgBit[(i + 1) * 8 - j - 1] = (msg[i] >> j) & 1;
		}
	}
} 

//�ַ�ת��Ϊ2���ƣ�2���ַ��� 
void charToBit1(char * msg, int* msgBit) {
	int i,j;
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			msgBit[(i + 1) * 8 - j - 1] = (msg[i] >> j) & 1;
		}
	}
} 

//������ת��Ϊ�ַ� 
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

//16����ת��Ϊ2���ƣ������128λ 
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
	//plaintextΪ�����ַ�����,��NULL��β
	//keytextΪ��Կ�ַ����飬��NULL��β
	//vitextΪ��ʼ�������ַ����飬��NULL��β
	//cipherΪ�����ַ����飬��NULL��β����Ҫ������䣬ע��Ҫ�ocipher����ռ䣡
	//��ʵ��~
	int i;//ѭ������ 
	int h;//ѭ������ 
	int j;//ѭ������ 
	int p=0;//���� 
	int pp=0;//���� 
	int size=16;//���μ��ܳ��� 
	char miwencbc[64];//cbc���ܵ����ĵ��ַ���ʾ 
	char mm[32];//����ַ� 
	int aaa[128];//����������� 
	char vitextt1[8];//��ʼ��������ǰ8λ 
	char vitextt2[8];//��ʼ�������ĺ�8λ 
	char jiemicbc[64];//���ܵ����� 
	char pfirst[16];//��һ��ת���������ַ���ʽ 
	char pfirst1[8];//��һ��ת���������ַ���ʽǰ8�ֽ� 
	char pfirst2[8];//��һ��ת���������ַ���ʽ��8�ֽ� 
	int vit1[64];//��ų�ʼ�������Ķ����Ʊ�ʾǰ64λ 
	int vit2[64];//��ų�ʼ�������Ķ����Ʊ�ʾ��64λ 
	int vit[128];//��ų�ʼ�������Ķ����Ʊ�ʾ 
	int plainfirst[128];//��һ��ת�������Ķ�������ʽ 
	int plainfirst1[64];//��һ��ת�������Ķ�������ʽǰ64λ 
	int plainfirst2[64];//��һ��ת�������Ķ�������ʽ��64λ 
	int plaina[128];//����Ķ����Ʊ�ʾ 
	int plaina1[64];//����Ķ����Ʊ�ʾǰ64λ 
	int plaina2[64];//����Ķ����Ʊ�ʾ��64λ 
	char mi1[8];//ǰ16�ֽڽ�����Ҫ�����Ŀ�ǰ8�ֽ� 
	char mi2[8];//ǰ16�ֽڽ�����Ҫ�����Ŀ��8�ֽ� 
	char mi3[8];//��16�ֽڽ�����Ҫ�����Ŀ�ǰ8�ֽ� 
	char mi4[8];//��16�ֽڽ�����Ҫ�����Ŀ��8�ֽ� 
	int mii1[64];//ǰ16�ֽڽ�����Ҫ�����Ŀ�ǰ64λ 
	int mii2[64];//ǰ16�ֽڽ�����Ҫ�����Ŀ��64λ 
	int mii3[64];//��16�ֽڽ�����Ҫ�����Ŀ�ǰ64λ 
	int mii4[64];//��16�ֽڽ�����Ҫ�����Ŀ��64λ 
	int mimi[128];//���Ľ��ܳ��������ĵĶ����� 
	int uu[128];//�Ĵ�128λ������ 
	int ooo[128];//�Ĵ�128λ������ 
	int mimimi[128];//���Ľ��ܳ��������ĵĶ�������� 
	char yy[2];//�Ĵ���ܵ��ַ� 
	int xx[8];//�Ĵ���ܵ��ַ��Ķ����� 
	int zz[128];//�Ĵ��һ�����ĵĶ����ƣ��������� 
	char zhuan[32];//ת�����ֽ� 
	int temp[8];//�Ĵ� 
	char tempc[1];//�Ĵ���ַ���ʾ 
	int tt; 
	char plainafter[16];//����һ��֮��ĺ���16�ֽ����� 
	char plainafter1[8];//ǰ8�ֽ� 
	char plainafter2[8];//��8�ֽ� 
    const uint8_t *data = (uint8_t*)plaintext;  
    uint8_t ct2[32] = {0};    //�ⲿ������������ڴ棬���ڴ�ż��ܺ�����
    uint8_t plain2[32] = {0}; //�ⲿ������������ڴ棬���ڴ�Ž��ܺ�����
       uint8_t plain3[32] = {0}; //�ⲿ������������ڴ棬���ڴ�Ž��ܺ�����
//����16�ֽ�����
//�Ƚ���ʼ������ת������Ϊ���õ�DES�ĺ�������64λ��ת��������16���ֽ�ת��Ϊ����8�ֽڵ����飬�ֱ�ת���ںϳɡ� 

    for(i=0;i<8;i++){
    	vitextt1[i]=vitext[i];
	}
	for(i=0;i<8;i++){
    	vitextt2[i]=vitext[i+8];	
	}
    charToBit(vitextt1,vit1);//ת��ǰ64λ 
    charToBit(vitextt2,vit2);//ת����64λ 
    for(i=0;i<64;i++){
    	vit[i]=vit1[i];
    	vit[i+64]=vit2[i];
	}
	
//ת�����ĵ������� ������ͬת����ʼ������ 
    for(i=0;i<8;i++){
    	pfirst1[i]=plaintext[i];
    	pfirst2[i]=plaintext[i+8];
	}
	charToBit(pfirst1,plainfirst1);//�ַ�ת������ 
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//��� 
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
	//������ת�ַ� 
	BitToChar(plaina1,plainafter1);
	BitToChar(plaina2,plainafter2);
	for(i=0;i<8;i++){
		plainafter[i]=plainafter1[i];
		plainafter[i+8]=plainafter2[i];
	}
    uint8_t dataa[16];   
    //���� 
    aesEncrypt(keytext, 16, plainafter, ct2, 16); 
    for(i=0;i<32;i++){
    	printhexin(ct2[i],i);
	}
    for(i=0;i<32;i++){
    	miwencbc[p]=miwen[i];//��ֵ���� 
    	zhuan[i]=miwencbc[p];
    	p++;    	
	}
	hextob(zhuan,zz);//16����ת�������� 
    // ����16�ֽ�����
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
	//��� 
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
	//16����ת�������� 
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
	//��� 
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
	//�ڶ��μ��� 
     aesEncrypt(keytext, 16, plainafter, ct2, 16); 
    for(i=0;i<32;i++){
    	printhexin(ct2[i],i);
	}
    for(i=0;i<32;i++){
    	miwencbc[p]=miwen[i];
    	p++;
	}
    // �ڶ��ν���16�ֽ�����
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
//    printf("%s", "���ܳ����Ľ���ǣ�");    
//	for(i=0;i<64;i++){
//		printf("%c",miwencbc[i]);
//	}
//	printf("%s\n","");
//	printf("%s","���ܳ����Ľ���ǣ�");
//	for(i=0;i<64;i++){
//		printf("%c",jiemicbc[i]);	
//	}
    FILE* fp = fopen(cipherfile, "a");
    fwrite(miwencbc,sizeof(char),64,fp);
	fclose(fp);
	FILE* fp1 = fopen("CBC����.txt", "a");
	fwrite(jiemicbc,sizeof(char),64,fp1);
	fclose(fp1);
    ciphertext=ct2;
}

//ʮ����ת�������� 
dtob(int a,int *b,int c){
	int i;
	int sum;
	for(i=0;i<8;i++){
		b[7+8*c-i]=a%2;
		a=a/2;
	}
}

//������ת���ַ���������8λ������ת��2λ16���ƣ�������DES�ĺ�����ֻ�������ڴˡ� 
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
	//plaintextΪ�����ַ�����,��NULL��β
	//keytextΪ��Կ�ַ����飬��NULL��β
	//vitextΪ��ʼ�������ַ����飬��NULL��β
	//cipherΪ�����ַ����飬��NULL��β����Ҫ������䣬ע��Ҫ�ocipher����ռ䣡
	//��ʵ��~
	 int i;//ѭ������ 
	 int h;//ѭ������ 
	 int tem[128];//�Ĵ�ct2�Ķ����ƣ���������� 
	char pfirst[16];//16�ֽ����� 
	char pfirst1[8];//16�ֽ����ĵ�ǰ8�ֽ� 
	char pfirst2[8];//16�ֽ����ĵĺ�8�ֽ� 
	int plainfirst[128];//16�ֽ����ĵĶ����Ʊ�ʾ 
	int plainfirst1[64];//16�ֽ����ĵĶ����Ʊ�ʾ��ǰ64λ 
	int plainfirst2[64];//16�ֽ����ĵĶ����Ʊ�ʾ ��64λ 
	int change[128];//�����ļĴ棬���ڸ���v���� 
	int out[128];//����� 
	int oo[8];//����� 
	char q[2];//�Ĵ����������ܳ��������� 
	int vitext1[64];//��ʼ��������ǰ64λ 
	int vitext2[64];//��ʼ�������ĺ�64λ 
	char vitextchar1[8];//��ʼ��������ǰ8�ֽ� 
	char vitextchar2[8];//��ʼ��������8�ֽ� 
	int vitextbit[128];//��ʼ����2���� 
	int w1[64];//�Ĵ� 
	int w2[64];//�Ĵ� 
	char jiemi[64];//���ܳ��������� 
	char mimi1[16];//��ż��ܺ�����ĵ�ǰ16�ֽ� 
	char mimi2[16];//��ż��ܺ�����ĵĺ�16�ֽ� 
	int mimimi1[128];//��ż��ܺ�����ĵ�ǰ128λ 
	int mimimi2[128];//��ż��ܺ�����ĵĺ�128λ 
	char aes[16];//���ܵļĴ� 
	char vitt[16];//���ܵļĴ� 
    const uint8_t *data = (uint8_t*)plaintext;  
    uint8_t ct2[32] = {0};    //�ⲿ������������ڴ棬���ڴ�ż��ܺ�����
    uint8_t plain2[32] = {0}; //�ⲿ������������ڴ棬���ڴ�Ž��ܺ�����

//�Ĵ���ܺͽ��ܵĳ�ʼ������ 
    for(i=0;i<16;i++){
 	    vitt[i]=vitext[i];
    }    
    for(i=0;i<16;i++){
    	aes[i]=vitext[i];
	}
	//���ܳ�ʼ�������Ĵ������ֽ�ת��Ϊ������ 
    for(i=0;i<8;i++){
    	vitextchar1[i]=vitext[i];
    	vitextchar2[i]=vitext[i+8];
	}
	//�ֽ�ת�������� 
	charToBit(vitextchar1,w1);
	charToBit(vitextchar2,w2); 
	for(i=0;i<64;i++){
		vitextbit[i]=w1[i];
		vitextbit[i+64]=w2[i];
	}
	//���ܵ����ĵĸ�ֵ 
	for(i=0;i<8;i++){
  		pfirst1[i]=plaintext[i];
 	   	pfirst2[i]=plaintext[i+8];
	}
	//�ֽ�ת�������� 
	charToBit(pfirst1,plainfirst1);
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//���� 
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, vitt, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);
   		}
   		//��� 
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
		//�������Ľ��ת���ַ� 
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		miwen[2*h+i]=q[i];
		}
		//����v���� 
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
		//������ת��Ϊ�ֽ� 
		BitToChar(vitext1,vitextchar1);
		BitToChar(vitext2,vitextchar2);	
		//���³�ʼ������ 
		for(i=0;i<8;i++){
			vitt[i]=vitextchar1[i];
			vitt[i+8]=vitextchar2[i];
		}
    }
    //�������16�ֽڵ����� 
    for(i=0;i<8;i++){
  		pfirst1[i]=plaintext[i+16];
 	   	pfirst2[i]=plaintext[i+24];
	}
	//�ֽ�ת�������� 
	charToBit(pfirst1,plainfirst1);
	charToBit(pfirst2,plainfirst2);
	for(i=0;i<64;i++){
		plainfirst[i]=plainfirst1[i];
		plainfirst[i+64]=plainfirst2[i];
	}
	//���� 
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, vitt, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);//ʮ����ת�������� 
   		}
   		//��� 
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
//    printf("���ܺ�����ģ�\n");
//    for (i = 0; i < 64; ++i) {
//        printf("%c", miwen[i]);
//    }
//    printf("\n���ܺ�����ģ�\n");	
    //���ܵ�һ�� ��16�ֽڣ�
	//���¸��³�ʼ������ 
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
//�������� 
    for(i=0;i<32;i++){
  		mimi1[i]=miwen[i];
	}
    hextob(mimi1,mimimi1);//16����ת��2���� 
	for(i=0;i<128;i++){
		plainfirst[i]=mimimi1[i];
	}
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, aes, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);//ʮ����ת�������� 
   		}
   		//��� 
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
		//�ó���� 
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	//��ֵ���� 
  	  	for(i=0;i<2;i++){
    		jiemi[2*h+i]=q[i];
		}
		//���³�ʼ������ 
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
    FILE* fp = fopen("CFB����.txt","a");
	fwrite(jiemi,sizeof(char),32,fp);
	fclose(fp);
    //���ܵڶ��� ��16�ֽ� 
    for(i=0;i<32;i++){
  		mimi1[i]=miwen[i+32];
	}
    hextob(mimi1,mimimi1);//16����ת�������� 
	for(i=0;i<128;i++){
		plainfirst[i]=mimimi1[i];
	}
    for(h=0;h<16;h++){
    	aesEncrypt(keytext, 16, aes, ct2, 16); 
    	for(i=0;i<16;i++){
	  	    dtob(ct2[i],tem,i);//ʮ����ת�������� 
   		}
   		//��� 
		for(i=0;i<8;i++){
			if(plainfirst[i+8*h]==tem[i]){
				out[i]=0;
			}
			else{
				out[i]=1;
			}
		}
		//����������jiemi��64�� 
  	    for(i=0;i<8;i++){
    		oo[i]=out[i];
		}
  	  	b1(oo,q);
  	  	for(i=0;i<2;i++){
    		jiemi[2*h+32+i]=q[i];
		}
		//���³�ʼ������ 
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
	FILE* fp2 = fopen("CFB����.txt", "a");
	fwrite(&jiemi[32],sizeof(char),32,fp2);
	fclose(fp2);
    // ��Ϊ����ǰ������Ϊ�ɼ��ַ����ַ�������ӡ���ܺ�������ַ��������ǰ���Ľ��жԱ�
   
    ciphertext=ct2;
	
}

//OFB�ı�������ͬ��CFB ���м亯������CFB�����Բ�������ϸע��
 
void OFB(const char* plaintext, const char* keytext, const char* vitext, char** cipher) {
	//plaintextΪ�����ַ�����,��NULL��β
	//keytextΪ��Կ�ַ����飬��NULL��β
	//vitextΪ��ʼ�������ַ����飬��NULL��β
	//cipherΪ�����ַ����飬��NULL��β����Ҫ������䣬ע��Ҫ�ocipher����ռ䣡
	//��ʵ��~
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
    uint8_t ct2[32] = {0};    //�ⲿ������������ڴ棬���ڴ�ż��ܺ�����
    uint8_t plain2[32] = {0}; //�ⲿ������������ڴ棬���ڴ�Ž��ܺ�����
    //����32�ֽ�����
    char vitt[16];
    char jie[16];
    for(i=0;i<16;i++){
    	vitt[i]=vitext[i];
    	jie[i]=vitext[i];
	}
	//��ʼ�������Ĵ��� 
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
	//���ĸ�ֵ 
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
	//����16�ֽ� 
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
    //���ĵĸ��� 
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
	//���ܺ�16�ֽ� 
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
	//��ʼ�����������ʼ�� 
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
	//���ĵĸ��� 
	for(i=0;i<32;i++){
		mimi[i]=miwen[i];
	}
	hextob(mimi,mimimi);
	for(i=0;i<128;i++){
		plainfirst[i]=mimimi[i];
	}
	//����ǰ16�ֽ� 
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
    //���ĵĸ��� 
    for(i=0;i<32;i++){
  		  	mimi[i]=miwen[i+32];
	}
    hextob(mimi,mimimi);
	for(i=0;i<128;i++){
		plainfirst[i]=mimimi[i];
	}
	//���ܺ�16�ֽ� 
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
    FILE* fp1 = fopen("OFB����.txt", "a");
	fwrite(jiemi,sizeof(char),64,fp1);
	fclose(fp1);
    // ��Ϊ����ǰ������Ϊ�ɼ��ַ����ַ�������ӡ���ܺ�������ַ��������ǰ���Ľ��жԱ�
 //   printf("���ܺ�����ģ�\n");
 //   for (i = 0; i < 64; ++i) {
 //       printf("%c", miwen[i]);
 //   }
 //   printf("%s\n"," ");
  //   printf("���ܺ�����ģ�\n");
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
	//argc ��ʾ�����ĸ�����argv��ʾÿ��������һ���ַ�������
	printf("argc:%d\n", argc);
	for (i = 0; i < argc; i++) {
		printf("%d : %s\n", i, argv[i]);
	}

	/*
	-p plainfile ָ�������ļ���λ�ú�����
	-k keyfile  ָ����Կ�ļ���λ�ú�����
	-v vifile  ָ����ʼ�������ļ���λ�ú�����
	-m mode  ָ�����ܵĲ���ģʽ
	-c cipherfile ָ�������ļ���λ�ú����ơ�
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

	printf("����������ɣ�\n");
	printf("����Ϊ�����ļ���λ�ú�����:%s\n", plainfile);
	printf("����Ϊ��Կ�ļ���λ�ú�����:%s\n", keyfile);
	if (strcmp(mode, "ECB") != 0) {
		printf("����Ϊ��ʼ�������ļ��ļ���λ�ú�����:%s\n", vifile);
	}
	printf("����Ϊ�����ļ���λ�ú�����:%s\n", cipherfile);
	printf("����Ϊ���ܵ�ģʽ:%s\n", mode);

	printf("���ڿ�ʼ��ȡ�ļ���\n");

	printf("��ȡ�����ļ�...\n");
	bool read_result = readfile2memory(plainfile, &plaintext);
	if (read_result == false) {
		printf("��ȡ�����ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
		exit(-1);
	}
	printf("��ȡ�����ļ��ɹ���\n");

	printf("��ȡ��Կ�ļ�...\n");
	read_result = readfile2memory(keyfile, &keytext);
	if (read_result == false) {
		printf("��ȡ��Կ�ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
		exit(-1);
	}
	printf("��ȡ��Կ�ļ��ɹ���\n");

	if (strcmp(mode, "ECB") != 0) {
		printf("��ȡ��ʼ�����ļ�...\n");
		read_result = readfile2memory(vifile, &vitext);
		if (read_result == false) {
			printf("��ȡ��ʼ�����ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
			exit(-1);
		}
		printf("��ȡ��ʼ�����ļ��ɹ���\n");
	}

	if (strcmp(mode, "ECB") == 0) {
		starttime=clock();
		for(i=0;i<81920;i++){
			ECB(&plaintext[32*i], keytext, &ciphertext);
		}		
		endtime=clock();
//		v=(float)(5*1000/(endtime-starttime));
		printf("\n������%d����\n",endtime-starttime);
//		printf("�ӽ����ٶ�Ϊ��%f Bytes/ms",v);
	}
	else if (strcmp(mode, "CBC") == 0) {
		starttime=clock();	
		for(i=0;i<81920;i++){
		    CBC(&plaintext[32*i], keytext, vitext, &ciphertext);			
		} 
        endtime=clock();
		printf("\n������%d����\n",endtime-starttime); 	
	}
	else if (strcmp(mode, "CFB") == 0) {
		starttime=clock();
		for(i=0;i<81920;i++){
			CFB(&plaintext[32*i], keytext, vitext, &ciphertext);
		}
		endtime=clock();
		printf("\n������%d����\n",endtime-starttime); 
	}
	else if (strcmp(mode, "OFB") == 0) {
		starttime=clock();
		for(i=0;i<81920;i++){
		    OFB(&plaintext[32*i], keytext, vitext, &ciphertext);
	    }
	    endtime=clock();
		printf("\n������%d����\n",endtime-starttime); 
	}
	else {
		//��Ӧ���ܵ�������
		printf("�������󣡣���\n");
		exit(-2);
	}
	if (ciphertext == NULL) {
		printf("ͬѧ��ciphertextû�з����ڴ�Ŷ����Ҫ��������~\nʧ�ܣ������˳���...");
		exit(-1);
	}
	int count = strlen(ciphertext);
	char* cipherhex = malloc(count * 2 + 1);
	memset(cipherhex, 0, count * 2 + 1);
	printf("%s\nд���ļ���...\n", cipherhex);
	printf("��ϲ������˸ó������ύ����!");
	return 0;
}
