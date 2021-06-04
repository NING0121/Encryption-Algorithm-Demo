/*
(DES算法实现）
4种操作模式-----ECB、CBC、CFB、OFB
*/
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdbool.h>
#include<math.h>
#include<time.h>
char command[150]; //命令数组 
//全局变量定义 
char argc[6][30];
char plainfile[30];
char keyfile[30];
char ivfile[30];
char mode[4];
char cipherfile[30];
char *plainText;	//明文串 
char *keyText;	//密钥串 
char *ivText;	//初始化向量串 
char *cipherText;	//密文
bool *binPlainText;	//二进制明文串
bool *binCipherText;	//二进制密文 
bool *binKeyText;	//二进制密钥串
bool *binIvText;	//二进制初始化向量串
int tokenNumber = 0;//存储分割出来的字段数量
long int sizePlain = 0;//Plain的大小
//函数声明 
int CommandTokens(); //命令行分段函数 
void Enread2memory();//加密前读文件
void Deread2memory();//解密前读文件 
void hex2Bin(char *string,bool *binString,long int num);//16进制转2进制 
void CreatKeyOfLoop(bool K[64],bool Key[16][48]);//生成轮密钥
void Xor(bool *DatA,bool *DatB);//异或函数
void En_DES(bool M[64],bool K[64],char final[16]);//DES加密 
void De_DES(bool M[64],bool K[64],char final[16]);//DES解密 
//ECB 
void ECB(); 
void En_ECB();
void De_ECB();
//CBC 
void CBC();
void En_CBC();
void De_CBC();
//CFB 
void CFB();
void En_CFB();
void De_CFB();
//OFB 
void OFB();
void En_OFB();
void De_OFB();
void RegisterMove(bool r[64],bool in[]);




//移位操作
void RegisterMove(bool r[64],bool in[]){
	int i =0;
	for(i=0;i<56;i++){
		r[i] = r[i+8];
	}
	for(i=56;i<64;i++){
		r[i] = in[i-56];
	}
} 

//命令行分段 
int CommandTokens(){
	char * token;
	int n = 0;
	token = strtok(command,"-");//将command中的“-”用\0替代实现分割 
	strcpy(argc[n++],token);
	while(token!=NULL){
		token = strtok(NULL,"-");
		if(token!=NULL){
			strcpy(argc[n++],token);		
		}
	}
	return n;//i表示分割出的字段数量
}

// 加密前把文件数据读到内存中，并把文件转成二进制 
void Enread2memory(){
	int i = 1;
	for (i=1;i<tokenNumber;i++){
//		printf("Comand No.%d: %s\n",i,argc[i]);
		//根据当前命令段，读取相应的文件 
		switch(argc[i][0]){
			//读plainfile 
			case 'p':{
//				printf("plainfile : %s\n",plainfile);
				FILE* fp = fopen(plainfile,"r");
				if(fp==NULL)exit(1);//fp=NULL 文件打开失败，退出 
				fseek(fp,0,SEEK_END); //定位文件读写指针
				
				int size = ftell(fp);//文件字节数
			
				fseek(fp, 0, SEEK_SET);//重定位文件读写指针到文件开始位置
				
				plainText = malloc(size+1);//给plainText明文分配内存
				
				binPlainText = malloc(size*sizeof(bool)*4);//给二进制的plainText明文分配内存 
				plainText[size] = '\0';
				sizePlain = size;
				fread(plainText, size, 1, fp);//从文件中读取size个字节到内存块中
				fclose(fp);	 
//				printf("PlainText: %s\n",plainText);
				int j =0;
				printf("PlainText（明文）: ");
				for(j=0;j<16;j++)printf("%c",plainText[j]); 
				printf("...\n");
				break;
			}
			case 'k':{
//				printf("keyfile : %s\n",keyfile);
				FILE* fp = fopen(keyfile,"r");
				
				if(fp==NULL)exit(1);//fp=NULL 文件打开失败，退出
				fseek(fp,0,SEEK_END);//定位文件读写指针
				
				int size = ftell(fp);//文件字节数 
				
				fseek(fp, 0, SEEK_SET);//重定位文件读写指针到文件开始位置 
			
				keyText = malloc(size+1);	//给keyText分配内存
				 
				binKeyText = malloc(size*sizeof(bool)*4);//给二进制的keyText分配内存
				keyText[size] = '\0';
				fread(keyText, size, 1, fp);//从文件中读取size个字节到内存块中
				fclose(fp);	 
				printf("KeyText（密文）: %s\n",keyText);
				hex2Bin(keyText,binKeyText,size);
				break;
			}
			case 'v':{
//				printf("ivfile : %s\n",ivfile);
				FILE* fp = fopen(ivfile,"r");
			
				if(fp==NULL)exit(1);//fp=NULL 文件打开失败，退出
				fseek(fp,0,SEEK_END);//定位文件读写指针
			
				int size = ftell(fp);	//文件字节数 
			
				fseek(fp, 0, SEEK_SET);	//重定位文件读写指针到文件开始位置 
				
				ivText = malloc(size+1);//给ivText分配内存
				
				binIvText = malloc(size*sizeof(bool)*4);//给二进制的ivText分配内存 
				ivText[size] = '\0';
				fread(ivText, size, 1, fp);//从文件中读取size个字节到tmp内存块中
				fclose(fp);
				printf("IvText（初始化向量）: %s\n",ivText);
				hex2Bin(ivText,binIvText,size);					
				break;
			}
			case 'm':{
//				printf("mode : %s\n",mode);
				break;
			}
			case 'c':{
//				printf("cipherfile : %s\n",cipherfile);					
				break;
			}
			default:break;				
		}
	}
}
//============================================================================== 
//============================================================================== 

//DES算法部分（已知部分） 
//hex to Bin 十六进制转二进制
void hex2Bin(char *string,bool *binString,long int num){
	strupr(string);
	int m = 0;
	int n = 0;
	char tem = 0;
	char table[16][5] = {
		"0000","0001","0010","0011",
		"0100","0101","0110","0111",
		"1000","1001","1010","1011",
		"1100","1101","1110","1111"
	}; 
	for(m=0;m<num;m++){ 
		if(string[m]>='A'){
			tem=string[m]-'A'+10;//根据ASCII将其化为对应的数
		}else{
			tem = string[m] - '0';	
		}
		for(n=0;n<4;n++){
			binString[m*4+n]=table[tem][n]-'0';
//			printf("%d",binString[i*4+j]);
		}
//		printf("   "); 
	}
//	printf("\n"); 
}

//IP初始置换
void IP_change(bool M[64]){
	int IP[64] = {58,50,42,34,26,18,10,2,
			  	  60,52,44,36,28,20,12,4,
			  	  62,54,46,38,30,22,14,6,
			  	  64,56,48,40,32,24,16,8,
			  	  57,49,41,33,25,17,9,1,
			  	  59,51,43,35,27,19,11,3,
			  	  61,53,45,37,29,21,13,5,
			  	  63,55,47,39,31,23,15,7};
	bool New_M[64];
	int i;
	for (i=0;i<64;i++){
		New_M[i]=M[IP[i]-1];
	}
	for(i=0;i<64;i++){
		M[i]=New_M[i];
	}
}

//IP逆置换
void IP_reverse(bool M[64]){
	int IP[64] = {40,8,48,16,56,24,64,32,
				  39,7,47,15,55,23,63,31,
				  38,6,46,14,54,22,62,30,
				  37,5,45,13,53,21,61,29,
				  36,4,44,12,52,20,60,28,
				  35,3,43,11,51,19,59,27,
				  34,2,42,10,50,18,58,26,
				  33,1,41,9,49,17,57,25};
	int New_M[64];
	int i;
	for (i=0;i<64;i++){
		New_M[i]=M[IP[i]-1];
	}
	for(i=0;i<64;i++){
		M[i]=New_M[i];
	}
}

//F_函数 
void F_function(bool R1[32],bool K[48],bool result[32]){
	int i,m,n,j,num;
	bool E[48];
	bool B[48];
	bool C[32];
	int pre[48]={32,1,2,3,4,5,		//预扩展 
			   4,5,6,7,8,9,
			   8,9,10,11,12,13,
			   12,13,14,15,16,17,
			   16,17,18,19,20,21,
			   20,21,22,23,24,25,
			   24,25,26,27,28,29,
			   28,29,30,31,32,1}; 
	int S_Box[8][4][16]=
{
    {
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    }
};

	int P_Box[32]={16,7,20,21,29,12,28,17,
				   1,15,23,26,5,18,31,10,
				   2,8,24,14,32,27,3,9,
				   19,13,30,6,22,11,4,25};
	for(i=0;i<48;i++){
			E[i]=R1[pre[i]-1];
			if(E[i]==K[i]) B[i]=0; //异或 
			else B[i]=1;
		}
	for(i=0;i<8;i++){
		m = B[6*i+1]*8+B[6*i+2]*4+B[6*i+3]*2+B[6*i+4];
		n = B[6*i]*2+B[6*i+5];
		num = S_Box[i][n][m];
		for(j=0;j<4;j++){
			if(num>=pow(2,3-j)){
				num = num-pow(2,3-j);
				C[4*i+j]=1;
			} 
			else C[4*i+j]=0;	
		}
	}	
	for(i=0;i<32;i++){
		result[i]=C[P_Box[i]-1];
	}
}

//异或函数
void Xor(bool *DatA,bool *DatB){
	int i=0;
	for(i=0;i<64;i++)
	{
		DatA[i]=DatA[i]^DatB[i];                  // 异或 
	}
}

//异或函数 
void Xor_8(bool *DatA,bool *DatB){
	int i=0;
	for(i=0;i<8;i++)
	{
		DatA[i]=DatA[i]^DatB[i];                  // 异或 
	}	
}  

//生成轮密钥
void CreatKeyOfLoop(bool K[64],bool Key[16][48]){
	int C0[28],D0[28];
	int C1[28],D1[28];
	int temp[56];
	int a[2],b[2];
	int i,j,loop;
	int LS[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	int PC_1[56]={57,49,41,33,25,17,9,
				  1,58,50,42,34,26,18,
				  10,2,59,51,43,35,27,
				  19,11,3,60,52,44,36,
				  63,55,47,39,31,23,15,
				  7,62,54,46,38,30,22,
				  14,6,61,53,45,37,29,
				  21,13,5,28,20,12,4};
	int PC_2[48]={14,17,11,24,1,5,3,28,
				  15,6,21,10,23,19,12,4,
				  26,8,16,7,27,20,13,2,
				  41,52,31,37,47,55,30,40,
				  51,45,33,48,44,49,39,56,
				  34,53,46,42,50,36,29,32};
	for(i=0;i<28;i++){
		C0[i]=K[PC_1[i]-1];
		D0[i]=K[PC_1[i+28]-1]; 		//去掉奇偶校验并置换 
	}
	for(loop=0;loop<16;loop++){
		for(i=0;i<LS[loop];i++){
			a[i]=C0[i];
			b[i]=D0[i];
		} 
		for(i=0;i<28-LS[loop];i++){ 
			C1[i]=C0[i+LS[loop]];
			D1[i]=D0[i+LS[loop]];
		}
		for(i=28-LS[loop];i<28;i++){
			C1[i]=a[i+LS[loop]-28];
			D1[i]=b[i+LS[loop]-28];
		}
		for(i=0;i<28;i++){
			temp[i]=C1[i];
			temp[i+28]=D1[i];
		}
		for(i=0;i<28;i++){
			C0[i]=C1[i];
			D0[i]=D1[i];
		}
		for(i=0;i<48;i++){
			Key[loop][i]=temp[PC_2[i]-1];
		}
	}
} 

//DES加密 
void En_DES(bool M[64],bool K[64],char final[16]){
	int i,loop,num;
	bool L1[32],R1[32];		//一轮加密之前分组
	bool L2[32],R2[32];		//一轮加密后分组 
	bool Key[16][48];
	bool result[32];			//F函数得到的结果  
	bool finalB[64];
	bool M2[64];
	for(i=0;i<64;i++)M2[i]=M[i];
	IP_change(M2);	//IP置换 
	for(i=0;i<32;i++){
		L1[i]=M2[i];
		R1[i]=M2[i+32];
	}
	CreatKeyOfLoop(K,Key);	//生成密钥 
	for(loop=0;loop<16;loop++){	//16轮加密 
		for(i=0;i<32;i++) L2[i]=R1[i];
		F_function(R1,Key[loop],result);
		for(i=0;i<32;i++){
			if(result[i]==L1[i]) R2[i]=0;
			else R2[i]=1;
		} 
		for(i=0;i<32;i++){
			L1[i]=L2[i];
			R1[i]=R2[i];
		}
	}
	for(i=0;i<32;i++){
		finalB[i]=R2[i];		//L和R交换位置 
		finalB[i+32]=L2[i];
	}
	IP_reverse(finalB);
	for(i=0;i<16;i++){
		num=finalB[4*i]*8+finalB[4*i+1]*4+finalB[4*i+2]*2+finalB[4*i+3];
		if(num>=0&&num<=9) final[i]='0'+num;
		else final[i]='A'+num-10;
	} 
}

//DES解密
void De_DES(bool M[64],bool K[64],char final[16]){
	int i,loop,num;
	bool L1[32],R1[32];		//一轮加密之前分组
	bool L2[32],R2[32];		//一轮加密后分组 
	bool Key[16][48];
	bool result[32];			//F函数得到的结果  
	bool finalB[64];
	bool M2[64];
	for (i=0;i<64;i++)M2[i]=M[i];
	IP_change(M2);	//IP置换 
	for(i=0;i<32;i++){
		L1[i]=M2[i];
		R1[i]=M2[i+32];
	}
	CreatKeyOfLoop(K,Key);	//生成密钥 
	for(loop=0;loop<16;loop++){	//16轮加密 
		for(i=0;i<32;i++) L2[i]=R1[i];
		F_function(R1,Key[15-loop],result);
		for(i=0;i<32;i++){
			if(result[i]==L1[i]) R2[i]=0;
			else R2[i]=1;
		} 
		for(i=0;i<32;i++){
			L1[i]=L2[i];
			R1[i]=R2[i];
		}
	}
	for(i=0;i<32;i++){
		finalB[i]=R2[i];		//L和R交换位置 
		finalB[i+32]=L2[i];
	}
	IP_reverse(finalB);
	for(i=0;i<16;i++){
		num=finalB[4*i]*8+finalB[4*i+1]*4+finalB[4*i+2]*2+finalB[4*i+3];
		if(num>=0&&num<=9) final[i]='0'+num;
		else final[i]='A'+num-10;
	} 
}
//============================================================================== 
//============================================================================== 
//ECB模式
void ECB(){
	//第一次测试加密 
	Enread2memory();
	//给密文分配空间 
	cipherText = malloc(sizePlain+1);
	binCipherText = malloc(sizePlain*4); 
	cipherText[sizePlain] = '\0';
	printf("...开始加密测试,生成密文\n...正在写入密文文件\n");	
	En_ECB();
	FILE *fp =fopen(cipherfile,"w");
	if(fp==NULL)exit(1);
	fputs(cipherText,fp); 
	fclose(fp);
//	De_ECB();
	//开始计时 
	time_t c_start,c_end;
	c_start = clock();
	int count = 1;
	printf("...开始20次加解密时间检测\n");
	for(;count<=20;count++){
		printf("NO.%d加解密：\n",count); 
		En_ECB();
		De_ECB();
	}
	//结束计时 
	c_end = clock();
	printf("ECB 20次加解密耗时为%lfMS\n",difftime(c_end,c_start));	 
}
//En_ECB ECB加密 
void En_ECB(){
	int i =0;
	hex2Bin(plainText,binPlainText,sizePlain);
	//64位一组，把密文分成若干组
	int groupNum = sizePlain*4/64; 
	bool currentPlain[64];
	char final[17];
	final[16] = '\0';
	for(i=0;i<groupNum;i++){
		//第i组 
		int j=0;
		for(j=0;j<64;j++){
			currentPlain[j] = binPlainText[j+i*64];
		}
		En_DES(currentPlain,binKeyText,final);
		for(j=0;j<16;j++){
			cipherText[i*16+j] = final[j];
		}
	}
//	printf("CipherText: %s\n",cipherText);
	printf("CipherText: ");
	for(i=0;i<16;i++)printf("%c",cipherText[i]); 
	printf("...\n");
}
//De_ECB ECB解密 
void De_ECB(){
	int i =0;
	hex2Bin(cipherText,binCipherText,sizePlain);
	//64位一组，把密文分成若干组
	int groupNum = sizePlain*4/64; 
	bool currentCipher[64];
	char final[17];
	final[16] = '\0';
	for(i=0;i<groupNum;i++){
		//第i组 
		int j=0;
		for(j=0;j<64;j++){
			currentCipher[j] = binCipherText[j+i*64];
		}
		De_DES(currentCipher,binKeyText,final);
		for(j=0;j<16;j++){
			plainText[i*16+j] = final[j];
		}
	}
//	printf("PlainText: %s\n",plainText);
	printf("PlainText: ");
	for(i=0;i<16;i++)printf("%c",plainText[i]); 
	printf("...\n");
} 
//============================================================================== 
//============================================================================== 

//CBC模式
void CBC(){
	//第一次测试加密 
	Enread2memory();
	//给密文分配空间 
	cipherText = malloc(sizePlain+1);
	binCipherText = malloc(sizePlain*4); 
	cipherText[sizePlain] = '\0';
	printf("...开始加密测试,生成密文\n...正在写入密文文件\n");
	En_CBC();
	FILE *fp =fopen(cipherfile,"w");
	if(fp==NULL)exit(1);
	fputs(cipherText,fp); 
	fclose(fp);
//	De_CBC();
	printf("...开始20次加解密时间检测\n");
	//开始计时 
	time_t c_start,c_end;
	c_start = clock();
	int count = 1;
	for(;count<=20;count++){
		printf("NO.%d加解密：\n",count); 
		En_CBC();
		De_CBC();
	}
	//结束计时 
	c_end = clock();
	printf("CBC 20次加解密耗时为%lfMS\n",difftime(c_end,c_start));
}

//En_CBC CBC加密 
void En_CBC(){
	int i =0;
	hex2Bin(plainText,binPlainText,sizePlain);
	int groupNum = sizePlain*4/64; 
	bool currentPlain[64];
	char final[16];
	bool binFinal[64];
	for (i=0;i<16;i++){
		final[i] = ivText[i];
	}
	for(i=0;i<groupNum;i++){
		//第i组 
		int j=0;
		for(j=0;j<64;j++){
			currentPlain[j] = binPlainText[j+i*64];
		}
		hex2Bin(final,binFinal,16);
		//先异或，再加密 
		Xor(currentPlain,binFinal);
		En_DES(currentPlain,binKeyText,final);
		for(j=0;j<16;j++){
			cipherText[i*16+j] = final[j];
		}
	}
//	printf("CipherText: %s\n",cipherText);
	printf("cipherText: ");
	for(i=0;i<16;i++)printf("%c",cipherText[i]); 
	printf("...\n"); 
}

//De_CBC CBC解密 
void De_CBC(){
	int i =0;
	hex2Bin(cipherText,binCipherText,sizePlain);
	//分组个数 
	int groupNum = sizePlain*4/64; 
	bool currentCipher[64];//当前密文分组 
	char final[16];
	bool binFinal[64];
	bool IV[64];
	for (i=0;i<64;i++){
		IV[i] = binIvText[i];
	}
	for(i=0;i<groupNum;i++){
		//第i组 
		int j=0;
		//当前密文分组 
		for(j=0;j<64;j++){
			currentCipher[j] = binCipherText[j+i*64];
		}
		//先解密再异或 
		De_DES(currentCipher,binKeyText,final);
		hex2Bin(final,binFinal,16);
		Xor(binFinal,IV);//异或 
		//二进制转16进制 
		for(j=0;j<16;j++){
			final[j] = 8*binFinal[j*4] + 4*binFinal[j*4+1] + 2*binFinal[j*4+2] + binFinal[j*4+3];
			if(final[j]>=10){
				final[j] = final[j] -10 + 'A';
			}
			else{
				final[j] = final[j] + '0';
			}
		} 
		//迭代IV 
		for(j=0;j<64;j++){
			IV[j] = binCipherText[j+i*64];
		}
		for(j=0;j<16;j++){
			plainText[i*16+j] = final[j];
		}
	}
//	printf("PlainText: %s\n",plainText);
	printf("PlainText: ");
	for(i=0;i<16;i++)printf("%c",plainText[i]); 
	printf("...\n"); 
}
//============================================================================== 
//============================================================================== 

//OFB模式
void OFB(){
	//第一次测试加密 
	Enread2memory();
	//给密文分配空间 
	cipherText = malloc(sizePlain+1);
	binCipherText = malloc(sizePlain*4); 
	cipherText[sizePlain] = '\0';
	printf("...开始加密测试,生成密文\n...正在写入密文文件\n");
	En_OFB();
	FILE *fp =fopen(cipherfile,"w");
	if(fp==NULL)exit(1);
	fputs(cipherText,fp); 
	fclose(fp);
//	De_OFB();
	printf("...开始20次加解密时间检测\n");
	time_t c_start,c_end;
	c_start = clock();
	int i =0;
	for(i=0;i<20;i++){
		printf("NO.%d加解密：",i+1);
		En_OFB();
		De_OFB();
	}
	c_end = clock();
	printf("共耗时%lf MS\n",difftime(c_end,c_start));	
}

//En_OFB
void En_OFB(){
	hex2Bin(plainText,binPlainText,sizePlain);
	bool binZ[64];
	int i = 0;
	int groupNum = sizePlain*4/64;
	char final[17];
	bool binFinal[64];
	bool end[64];
	for(i=0;i<64;i++)binZ[i] = binIvText[i];
	for(i=0;i<groupNum*8;i++){
		//8个一组，第i组 
		int j = 0;
		bool tem[8];
		bool current[8]; //当前明文分组 
		En_DES(binZ,binKeyText,final);
		hex2Bin(final,binFinal,16);
//		printf("\nNO.%d  binZ:",i);
//		for(j=0;j<64;j++)printf("%d",binZ[j]);
//		printf("\n");
		//迭代binZ
		RegisterMove(binZ,binFinal);			
		for(j=0;j<8;j++)tem[j]=binFinal[j];
		for(j=0;j<8;j++)current[j] = binPlainText[i*8+j];
		Xor_8(tem,current);
		//转16进制并写入cipherText
		for(j=0;j<2;j++){
			char sum = tem[j*4]*8 + tem[j*4+1]*4 + tem[j*4+2]*2 + tem[j*4+3];
			if(sum>=10)sum = sum - 10 +'A';
			else sum = sum + '0';
			cipherText[i*2+j] = sum;
		} 
	}
//	printf("%s\n",cipherText);
	printf("CipherText: ");
	for(i=0;i<16;i++)printf("%c",cipherText[i]); 
	printf("...\n");
	
}

//De_OFB
void De_OFB(){
	hex2Bin(cipherText,binCipherText,sizePlain);
	bool binZ[64];
	int i = 0;
	int groupNum = sizePlain*4/64;
	char final[17];
	bool binFinal[64];
	bool end[64];
	for(i=0;i<64;i++)binZ[i] = binIvText[i];
	for(i=0;i<groupNum*8;i++){
		//8个一组，第i组 
		int j = 0;
		bool tem[8];
		bool current[8]; //当前密文分组 
		En_DES(binZ,binKeyText,final);
		hex2Bin(final,binFinal,16);
//		printf("\nNO.%d  binZ:",i);
//		for(j=0;j<64;j++)printf("%d",binZ[j]);
//		printf("\n");
		//迭代binZ
		RegisterMove(binZ,binFinal);			
		for(j=0;j<8;j++)tem[j]=binFinal[j];
		for(j=0;j<8;j++)current[j] = binCipherText[i*8+j];
		Xor_8(tem,current);
		//转16进制并写入plainText
		for(j=0;j<2;j++){
			char sum = tem[j*4]*8 + tem[j*4+1]*4 + tem[j*4+2]*2 + tem[j*4+3];
			if(sum>=10)sum = sum - 10 +'A';
			else sum = sum + '0';
			plainText[i*2+j] = sum;
		} 
	}
//	printf("PlainText: %s\n",plainText);
	printf("PlainText: ");
	for(i=0;i<16;i++)printf("%c",plainText[i]); 
	printf("...\n");		
}
//==============================================================================
//============================================================================== 
 
//CFB模式
void CFB(){
	//第一次测试加密 
	Enread2memory();
	//给密文分配空间 
	cipherText = malloc(sizePlain+1);
	binCipherText = malloc(sizePlain*4); 
	cipherText[sizePlain] = '\0';
	printf("...开始加密测试,生成密文\n...正在写入密文文件\n");
	En_CFB();
	FILE *fp =fopen(cipherfile,"w");
	if(fp==NULL)exit(1);
	fputs(cipherText,fp); 
	fclose(fp);
//	De_CFB();
	printf("...开始20次加解密时间检测\n");
	time_t c_start,c_end;
	c_start = clock();
	int i =0;
	for(i=0;i<20;i++){
		printf("NO.%d加解密：\n",i+1);
		En_CFB();
		De_CFB();
	}
	c_end = clock();
	printf("共耗时%lf MS\n",difftime(c_end,c_start));	
} 

//En_CFB
void En_CFB(){
	hex2Bin(plainText,binPlainText,sizePlain);
	bool binZ[64];
	int i = 0;
	int groupNum = sizePlain*4/64;
	char final[17];
	bool binFinal[64];
	bool end[64];
	for(i=0;i<64;i++)binZ[i] = binIvText[i];
	for(i=0;i<groupNum*8;i++){
		//8个一组，第i组 
		int j = 0;
		bool tem[8];
		bool current[8]; //当前明文分组 
		En_DES(binZ,binKeyText,final);
		hex2Bin(final,binFinal,16);
//		printf("\nNO.%d  binZ:",i);
//		for(j=0;j<64;j++)printf("%d",binZ[j]);
//		printf("\n");			
		for(j=0;j<8;j++)tem[j]=binFinal[j];
		for(j=0;j<8;j++)current[j] = binPlainText[i*8+j];
		Xor_8(tem,current);
		//迭代binZ
		RegisterMove(binZ,tem);
		//转16进制并写入cipherText
		for(j=0;j<2;j++){
			char sum = tem[j*4]*8 + tem[j*4+1]*4 + tem[j*4+2]*2 + tem[j*4+3];
			if(sum>=10)sum = sum - 10 +'A';
			else sum = sum + '0';
			cipherText[i*2+j] = sum;
		} 
	}
//	printf("CipherText: %s\n",cipherText);
	printf("CipherText: ");
	for(i=0;i<16;i++)printf("%c",cipherText[i]); 
	printf("...\n");	
}

//De_CFB
void De_CFB(){
	hex2Bin(cipherText,binCipherText,sizePlain);
	bool binZ[64];
	int i = 0;
	int groupNum = sizePlain*4/64;
	char final[17];
	bool binFinal[64];
	bool end[64];
	for(i=0;i<64;i++)binZ[i] = binIvText[i];
	for(i=0;i<groupNum*8;i++){
		//8个一组，第i组 
		int j = 0;
		bool tem[8];
		bool current[8]; //当前密文分组 
		En_DES(binZ,binKeyText,final);
		hex2Bin(final,binFinal,16);
//		printf("\nNO.%d  binZ:",i);
//		for(j=0;j<64;j++)printf("%d",binZ[j]);
//		printf("\n");			
		for(j=0;j<8;j++)tem[j]=binFinal[j];
		for(j=0;j<8;j++)current[j] = binCipherText[i*8+j];
		Xor_8(tem,current);
		//迭代binZ
		RegisterMove(binZ,current);
		//转16进制并写入plainText
		for(j=0;j<2;j++){
			char sum = tem[j*4]*8 + tem[j*4+1]*4 + tem[j*4+2]*2 + tem[j*4+3];
			if(sum>=10)sum = sum - 10 +'A';
			else sum = sum + '0';
			plainText[i*2+j] = sum;
		} 
	}
//	printf("PlainText: %s\n",plainText);
//打印前十六位;
	printf("PlainText: ");
	for(i=0;i<16;i++)printf("%c",plainText[i]); 
	printf("...\n");
}
//============================================================================== 
//============================================================================== 

int main(void){
	int i = 0;
	printf("(提示例子： eldes -p ./des_plain.txt -k ./des_key.txt -m ECB -v ./des_vi.txt -c ./des_cipher_ECB.txt Mode :ECB)"); 
	while(1){
		printf("Please enter your command:  " );
		gets(command);
		tokenNumber = CommandTokens();
		//解析命令 
		for (i=1;i<tokenNumber;i++){
//			printf("Comand No.%d: %s\n",i,argc[i]);
			//根据当前命令段，给相应的文件赋名字 
			switch(argc[i][0]){
				case 'p':{
					strcpy(plainfile,&argc[i][2]);
//					printf("plainfile : %s\n",plainfile);
					break;
				}
				case 'k':{
					strcpy(keyfile,&argc[i][2]);
//					printf("keyfile : %s\n",keyfile);
					break;
				}
				case 'v':{
					strcpy(ivfile,&argc[i][2]);
//					printf("ivfile : %s\n",ivfile);					
					break;
				}
				case 'm':{
					strcpy(mode,&argc[i][2]);
					mode[3]='\0';
//					printf("mode : %s\n",mode);
					break;
				}
				case 'c':{
					strcpy(cipherfile,&argc[i][2]);
//					printf("cipherfile : %s\n",cipherfile);					
					break;
				}
				default:break;				
			}
		}
		//根据mode进行加解密
		strupr(mode);
		printf("Mode :%s\n",mode);
		if(strcmp(mode,"ECB")==0){
			ECB();
		}
		else if(strcmp(mode,"CBC")==0){
			CBC();
		}
		else if(strcmp(mode,"CFB")==0){
			CFB();
		}
		else if(strcmp(mode,"OFB")==0){
			OFB();
		}
		else{
			puts("模式输入不正确（正确的有 ECB、CBC、CFB、OFB）");
			continue;
		}

	}
}
