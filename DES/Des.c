/*
(DES�㷨ʵ�֣�
4�ֲ���ģʽ-----ECB��CBC��CFB��OFB
*/
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdbool.h>
#include<math.h>
#include<time.h>
char command[150]; //�������� 
//ȫ�ֱ������� 
char argc[6][30];
char plainfile[30];
char keyfile[30];
char ivfile[30];
char mode[4];
char cipherfile[30];
char *plainText;	//���Ĵ� 
char *keyText;	//��Կ�� 
char *ivText;	//��ʼ�������� 
char *cipherText;	//����
bool *binPlainText;	//���������Ĵ�
bool *binCipherText;	//���������� 
bool *binKeyText;	//��������Կ��
bool *binIvText;	//�����Ƴ�ʼ��������
int tokenNumber = 0;//�洢�ָ�������ֶ�����
long int sizePlain = 0;//Plain�Ĵ�С
//�������� 
int CommandTokens(); //�����зֶκ��� 
void Enread2memory();//����ǰ���ļ�
void Deread2memory();//����ǰ���ļ� 
void hex2Bin(char *string,bool *binString,long int num);//16����ת2���� 
void CreatKeyOfLoop(bool K[64],bool Key[16][48]);//��������Կ
void Xor(bool *DatA,bool *DatB);//�����
void En_DES(bool M[64],bool K[64],char final[16]);//DES���� 
void De_DES(bool M[64],bool K[64],char final[16]);//DES���� 
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




//��λ����
void RegisterMove(bool r[64],bool in[]){
	int i =0;
	for(i=0;i<56;i++){
		r[i] = r[i+8];
	}
	for(i=56;i<64;i++){
		r[i] = in[i-56];
	}
} 

//�����зֶ� 
int CommandTokens(){
	char * token;
	int n = 0;
	token = strtok(command,"-");//��command�еġ�-����\0���ʵ�ַָ� 
	strcpy(argc[n++],token);
	while(token!=NULL){
		token = strtok(NULL,"-");
		if(token!=NULL){
			strcpy(argc[n++],token);		
		}
	}
	return n;//i��ʾ�ָ�����ֶ�����
}

// ����ǰ���ļ����ݶ����ڴ��У������ļ�ת�ɶ����� 
void Enread2memory(){
	int i = 1;
	for (i=1;i<tokenNumber;i++){
//		printf("Comand No.%d: %s\n",i,argc[i]);
		//���ݵ�ǰ����Σ���ȡ��Ӧ���ļ� 
		switch(argc[i][0]){
			//��plainfile 
			case 'p':{
//				printf("plainfile : %s\n",plainfile);
				FILE* fp = fopen(plainfile,"r");
				if(fp==NULL)exit(1);//fp=NULL �ļ���ʧ�ܣ��˳� 
				fseek(fp,0,SEEK_END); //��λ�ļ���дָ��
				
				int size = ftell(fp);//�ļ��ֽ���
			
				fseek(fp, 0, SEEK_SET);//�ض�λ�ļ���дָ�뵽�ļ���ʼλ��
				
				plainText = malloc(size+1);//��plainText���ķ����ڴ�
				
				binPlainText = malloc(size*sizeof(bool)*4);//�������Ƶ�plainText���ķ����ڴ� 
				plainText[size] = '\0';
				sizePlain = size;
				fread(plainText, size, 1, fp);//���ļ��ж�ȡsize���ֽڵ��ڴ����
				fclose(fp);	 
//				printf("PlainText: %s\n",plainText);
				int j =0;
				printf("PlainText�����ģ�: ");
				for(j=0;j<16;j++)printf("%c",plainText[j]); 
				printf("...\n");
				break;
			}
			case 'k':{
//				printf("keyfile : %s\n",keyfile);
				FILE* fp = fopen(keyfile,"r");
				
				if(fp==NULL)exit(1);//fp=NULL �ļ���ʧ�ܣ��˳�
				fseek(fp,0,SEEK_END);//��λ�ļ���дָ��
				
				int size = ftell(fp);//�ļ��ֽ��� 
				
				fseek(fp, 0, SEEK_SET);//�ض�λ�ļ���дָ�뵽�ļ���ʼλ�� 
			
				keyText = malloc(size+1);	//��keyText�����ڴ�
				 
				binKeyText = malloc(size*sizeof(bool)*4);//�������Ƶ�keyText�����ڴ�
				keyText[size] = '\0';
				fread(keyText, size, 1, fp);//���ļ��ж�ȡsize���ֽڵ��ڴ����
				fclose(fp);	 
				printf("KeyText�����ģ�: %s\n",keyText);
				hex2Bin(keyText,binKeyText,size);
				break;
			}
			case 'v':{
//				printf("ivfile : %s\n",ivfile);
				FILE* fp = fopen(ivfile,"r");
			
				if(fp==NULL)exit(1);//fp=NULL �ļ���ʧ�ܣ��˳�
				fseek(fp,0,SEEK_END);//��λ�ļ���дָ��
			
				int size = ftell(fp);	//�ļ��ֽ��� 
			
				fseek(fp, 0, SEEK_SET);	//�ض�λ�ļ���дָ�뵽�ļ���ʼλ�� 
				
				ivText = malloc(size+1);//��ivText�����ڴ�
				
				binIvText = malloc(size*sizeof(bool)*4);//�������Ƶ�ivText�����ڴ� 
				ivText[size] = '\0';
				fread(ivText, size, 1, fp);//���ļ��ж�ȡsize���ֽڵ�tmp�ڴ����
				fclose(fp);
				printf("IvText����ʼ��������: %s\n",ivText);
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

//DES�㷨���֣���֪���֣� 
//hex to Bin ʮ������ת������
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
			tem=string[m]-'A'+10;//����ASCII���仯Ϊ��Ӧ����
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

//IP��ʼ�û�
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

//IP���û�
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

//F_���� 
void F_function(bool R1[32],bool K[48],bool result[32]){
	int i,m,n,j,num;
	bool E[48];
	bool B[48];
	bool C[32];
	int pre[48]={32,1,2,3,4,5,		//Ԥ��չ 
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
			if(E[i]==K[i]) B[i]=0; //��� 
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

//�����
void Xor(bool *DatA,bool *DatB){
	int i=0;
	for(i=0;i<64;i++)
	{
		DatA[i]=DatA[i]^DatB[i];                  // ��� 
	}
}

//����� 
void Xor_8(bool *DatA,bool *DatB){
	int i=0;
	for(i=0;i<8;i++)
	{
		DatA[i]=DatA[i]^DatB[i];                  // ��� 
	}	
}  

//��������Կ
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
		D0[i]=K[PC_1[i+28]-1]; 		//ȥ����żУ�鲢�û� 
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

//DES���� 
void En_DES(bool M[64],bool K[64],char final[16]){
	int i,loop,num;
	bool L1[32],R1[32];		//һ�ּ���֮ǰ����
	bool L2[32],R2[32];		//һ�ּ��ܺ���� 
	bool Key[16][48];
	bool result[32];			//F�����õ��Ľ��  
	bool finalB[64];
	bool M2[64];
	for(i=0;i<64;i++)M2[i]=M[i];
	IP_change(M2);	//IP�û� 
	for(i=0;i<32;i++){
		L1[i]=M2[i];
		R1[i]=M2[i+32];
	}
	CreatKeyOfLoop(K,Key);	//������Կ 
	for(loop=0;loop<16;loop++){	//16�ּ��� 
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
		finalB[i]=R2[i];		//L��R����λ�� 
		finalB[i+32]=L2[i];
	}
	IP_reverse(finalB);
	for(i=0;i<16;i++){
		num=finalB[4*i]*8+finalB[4*i+1]*4+finalB[4*i+2]*2+finalB[4*i+3];
		if(num>=0&&num<=9) final[i]='0'+num;
		else final[i]='A'+num-10;
	} 
}

//DES����
void De_DES(bool M[64],bool K[64],char final[16]){
	int i,loop,num;
	bool L1[32],R1[32];		//һ�ּ���֮ǰ����
	bool L2[32],R2[32];		//һ�ּ��ܺ���� 
	bool Key[16][48];
	bool result[32];			//F�����õ��Ľ��  
	bool finalB[64];
	bool M2[64];
	for (i=0;i<64;i++)M2[i]=M[i];
	IP_change(M2);	//IP�û� 
	for(i=0;i<32;i++){
		L1[i]=M2[i];
		R1[i]=M2[i+32];
	}
	CreatKeyOfLoop(K,Key);	//������Կ 
	for(loop=0;loop<16;loop++){	//16�ּ��� 
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
		finalB[i]=R2[i];		//L��R����λ�� 
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
//ECBģʽ
void ECB(){
	//��һ�β��Լ��� 
	Enread2memory();
	//�����ķ���ռ� 
	cipherText = malloc(sizePlain+1);
	binCipherText = malloc(sizePlain*4); 
	cipherText[sizePlain] = '\0';
	printf("...��ʼ���ܲ���,��������\n...����д�������ļ�\n");	
	En_ECB();
	FILE *fp =fopen(cipherfile,"w");
	if(fp==NULL)exit(1);
	fputs(cipherText,fp); 
	fclose(fp);
//	De_ECB();
	//��ʼ��ʱ 
	time_t c_start,c_end;
	c_start = clock();
	int count = 1;
	printf("...��ʼ20�μӽ���ʱ����\n");
	for(;count<=20;count++){
		printf("NO.%d�ӽ��ܣ�\n",count); 
		En_ECB();
		De_ECB();
	}
	//������ʱ 
	c_end = clock();
	printf("ECB 20�μӽ��ܺ�ʱΪ%lfMS\n",difftime(c_end,c_start));	 
}
//En_ECB ECB���� 
void En_ECB(){
	int i =0;
	hex2Bin(plainText,binPlainText,sizePlain);
	//64λһ�飬�����ķֳ�������
	int groupNum = sizePlain*4/64; 
	bool currentPlain[64];
	char final[17];
	final[16] = '\0';
	for(i=0;i<groupNum;i++){
		//��i�� 
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
//De_ECB ECB���� 
void De_ECB(){
	int i =0;
	hex2Bin(cipherText,binCipherText,sizePlain);
	//64λһ�飬�����ķֳ�������
	int groupNum = sizePlain*4/64; 
	bool currentCipher[64];
	char final[17];
	final[16] = '\0';
	for(i=0;i<groupNum;i++){
		//��i�� 
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

//CBCģʽ
void CBC(){
	//��һ�β��Լ��� 
	Enread2memory();
	//�����ķ���ռ� 
	cipherText = malloc(sizePlain+1);
	binCipherText = malloc(sizePlain*4); 
	cipherText[sizePlain] = '\0';
	printf("...��ʼ���ܲ���,��������\n...����д�������ļ�\n");
	En_CBC();
	FILE *fp =fopen(cipherfile,"w");
	if(fp==NULL)exit(1);
	fputs(cipherText,fp); 
	fclose(fp);
//	De_CBC();
	printf("...��ʼ20�μӽ���ʱ����\n");
	//��ʼ��ʱ 
	time_t c_start,c_end;
	c_start = clock();
	int count = 1;
	for(;count<=20;count++){
		printf("NO.%d�ӽ��ܣ�\n",count); 
		En_CBC();
		De_CBC();
	}
	//������ʱ 
	c_end = clock();
	printf("CBC 20�μӽ��ܺ�ʱΪ%lfMS\n",difftime(c_end,c_start));
}

//En_CBC CBC���� 
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
		//��i�� 
		int j=0;
		for(j=0;j<64;j++){
			currentPlain[j] = binPlainText[j+i*64];
		}
		hex2Bin(final,binFinal,16);
		//������ټ��� 
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

//De_CBC CBC���� 
void De_CBC(){
	int i =0;
	hex2Bin(cipherText,binCipherText,sizePlain);
	//������� 
	int groupNum = sizePlain*4/64; 
	bool currentCipher[64];//��ǰ���ķ��� 
	char final[16];
	bool binFinal[64];
	bool IV[64];
	for (i=0;i<64;i++){
		IV[i] = binIvText[i];
	}
	for(i=0;i<groupNum;i++){
		//��i�� 
		int j=0;
		//��ǰ���ķ��� 
		for(j=0;j<64;j++){
			currentCipher[j] = binCipherText[j+i*64];
		}
		//�Ƚ�������� 
		De_DES(currentCipher,binKeyText,final);
		hex2Bin(final,binFinal,16);
		Xor(binFinal,IV);//��� 
		//������ת16���� 
		for(j=0;j<16;j++){
			final[j] = 8*binFinal[j*4] + 4*binFinal[j*4+1] + 2*binFinal[j*4+2] + binFinal[j*4+3];
			if(final[j]>=10){
				final[j] = final[j] -10 + 'A';
			}
			else{
				final[j] = final[j] + '0';
			}
		} 
		//����IV 
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

//OFBģʽ
void OFB(){
	//��һ�β��Լ��� 
	Enread2memory();
	//�����ķ���ռ� 
	cipherText = malloc(sizePlain+1);
	binCipherText = malloc(sizePlain*4); 
	cipherText[sizePlain] = '\0';
	printf("...��ʼ���ܲ���,��������\n...����д�������ļ�\n");
	En_OFB();
	FILE *fp =fopen(cipherfile,"w");
	if(fp==NULL)exit(1);
	fputs(cipherText,fp); 
	fclose(fp);
//	De_OFB();
	printf("...��ʼ20�μӽ���ʱ����\n");
	time_t c_start,c_end;
	c_start = clock();
	int i =0;
	for(i=0;i<20;i++){
		printf("NO.%d�ӽ��ܣ�",i+1);
		En_OFB();
		De_OFB();
	}
	c_end = clock();
	printf("����ʱ%lf MS\n",difftime(c_end,c_start));	
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
		//8��һ�飬��i�� 
		int j = 0;
		bool tem[8];
		bool current[8]; //��ǰ���ķ��� 
		En_DES(binZ,binKeyText,final);
		hex2Bin(final,binFinal,16);
//		printf("\nNO.%d  binZ:",i);
//		for(j=0;j<64;j++)printf("%d",binZ[j]);
//		printf("\n");
		//����binZ
		RegisterMove(binZ,binFinal);			
		for(j=0;j<8;j++)tem[j]=binFinal[j];
		for(j=0;j<8;j++)current[j] = binPlainText[i*8+j];
		Xor_8(tem,current);
		//ת16���Ʋ�д��cipherText
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
		//8��һ�飬��i�� 
		int j = 0;
		bool tem[8];
		bool current[8]; //��ǰ���ķ��� 
		En_DES(binZ,binKeyText,final);
		hex2Bin(final,binFinal,16);
//		printf("\nNO.%d  binZ:",i);
//		for(j=0;j<64;j++)printf("%d",binZ[j]);
//		printf("\n");
		//����binZ
		RegisterMove(binZ,binFinal);			
		for(j=0;j<8;j++)tem[j]=binFinal[j];
		for(j=0;j<8;j++)current[j] = binCipherText[i*8+j];
		Xor_8(tem,current);
		//ת16���Ʋ�д��plainText
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
 
//CFBģʽ
void CFB(){
	//��һ�β��Լ��� 
	Enread2memory();
	//�����ķ���ռ� 
	cipherText = malloc(sizePlain+1);
	binCipherText = malloc(sizePlain*4); 
	cipherText[sizePlain] = '\0';
	printf("...��ʼ���ܲ���,��������\n...����д�������ļ�\n");
	En_CFB();
	FILE *fp =fopen(cipherfile,"w");
	if(fp==NULL)exit(1);
	fputs(cipherText,fp); 
	fclose(fp);
//	De_CFB();
	printf("...��ʼ20�μӽ���ʱ����\n");
	time_t c_start,c_end;
	c_start = clock();
	int i =0;
	for(i=0;i<20;i++){
		printf("NO.%d�ӽ��ܣ�\n",i+1);
		En_CFB();
		De_CFB();
	}
	c_end = clock();
	printf("����ʱ%lf MS\n",difftime(c_end,c_start));	
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
		//8��һ�飬��i�� 
		int j = 0;
		bool tem[8];
		bool current[8]; //��ǰ���ķ��� 
		En_DES(binZ,binKeyText,final);
		hex2Bin(final,binFinal,16);
//		printf("\nNO.%d  binZ:",i);
//		for(j=0;j<64;j++)printf("%d",binZ[j]);
//		printf("\n");			
		for(j=0;j<8;j++)tem[j]=binFinal[j];
		for(j=0;j<8;j++)current[j] = binPlainText[i*8+j];
		Xor_8(tem,current);
		//����binZ
		RegisterMove(binZ,tem);
		//ת16���Ʋ�д��cipherText
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
		//8��һ�飬��i�� 
		int j = 0;
		bool tem[8];
		bool current[8]; //��ǰ���ķ��� 
		En_DES(binZ,binKeyText,final);
		hex2Bin(final,binFinal,16);
//		printf("\nNO.%d  binZ:",i);
//		for(j=0;j<64;j++)printf("%d",binZ[j]);
//		printf("\n");			
		for(j=0;j<8;j++)tem[j]=binFinal[j];
		for(j=0;j<8;j++)current[j] = binCipherText[i*8+j];
		Xor_8(tem,current);
		//����binZ
		RegisterMove(binZ,current);
		//ת16���Ʋ�д��plainText
		for(j=0;j<2;j++){
			char sum = tem[j*4]*8 + tem[j*4+1]*4 + tem[j*4+2]*2 + tem[j*4+3];
			if(sum>=10)sum = sum - 10 +'A';
			else sum = sum + '0';
			plainText[i*2+j] = sum;
		} 
	}
//	printf("PlainText: %s\n",plainText);
//��ӡǰʮ��λ;
	printf("PlainText: ");
	for(i=0;i<16;i++)printf("%c",plainText[i]); 
	printf("...\n");
}
//============================================================================== 
//============================================================================== 

int main(void){
	int i = 0;
	printf("(��ʾ���ӣ� eldes -p ./des_plain.txt -k ./des_key.txt -m ECB -v ./des_vi.txt -c ./des_cipher_ECB.txt Mode :ECB)"); 
	while(1){
		printf("Please enter your command:  " );
		gets(command);
		tokenNumber = CommandTokens();
		//�������� 
		for (i=1;i<tokenNumber;i++){
//			printf("Comand No.%d: %s\n",i,argc[i]);
			//���ݵ�ǰ����Σ�����Ӧ���ļ������� 
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
		//����mode���мӽ���
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
			puts("ģʽ���벻��ȷ����ȷ���� ECB��CBC��CFB��OFB��");
			continue;
		}

	}
}
