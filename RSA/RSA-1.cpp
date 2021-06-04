#include<stdlib.h>
#include<stdio.h>
#include<gmp.h>
#include<gmpxx.h>
#include<string.h>
#include<time.h>
#include <unistd.h>


//全局变量设定 
FILE *fp_plain=NULL;FILE *fp_pubkey=NULL;FILE *fp_prikey=NULL;FILE *fp_cipher=NULL;FILE *fp_sign=NULL;
FILE *fp_p=NULL;FILE *fp_q=NULL;FILE *fp_e=NULL;FILE *fp_d=NULL;FILE *fp_n=NULL;FILE *fp_m=NULL;
//文件指针 
char N_arr[30]={""};	
char plain_arr[30]={""}; 
char E_arr[10]={""};
char E_bi[20]={""};
char D_arr[30]={""};
char D_bi[200]={""};
//数据数组
//函数声明
int random(mpz_t p,mpz_t q,mpz_t N,mpz_t E,mpz_t D,mpz_t M);//随机生成函数 
int En_RSA(char E_bi[],mpz_t E,mpz_t C,mpz_t M,mpz_t N);//加密函数 
int De_RSA(char D_bin[],mpz_t D,mpz_t C,mpz_t M,mpz_t N);//解密函数 
long int c2i(char ch);//类型转换函数(字符到整型)
void test(mpz_t N,mpz_t M,mpz_t E,mpz_t C,mpz_t p,mpz_t q,mpz_t D);//测试函数 
void test_random(mpz_t p,mpz_t q,mpz_t N,mpz_t E,mpz_t D,mpz_t M,mpz_t C);//随机测试函数 	
 
//类型转换函数(字符到整型)
long int c2i(char ch)  
{  
    //判断是否为十进制数字，若为十进制数，则减去48（字符3十进制为53，十六进制3为十进制6） 
    if(isdigit(ch))  
        return ch - 48;  
    //判断是否为a-f（A-F） 
    if( ch < 'A' || (ch > 'F' && ch < 'a') || ch > 'z' )  
        return -1;  
    //判断是否为字母大写时减，小写时减 
    if(isalpha(ch))  
        return isupper(ch) ? ch - 55 : ch - 87;  
    return -1;  
}

//设定密钥函数 随机生成 
int random(mpz_t p,mpz_t q,mpz_t N,mpz_t E,mpz_t D,mpz_t M){
	mpz_t N_Ef;mpz_init(N_Ef);//定义N、p、q的欧拉值并且初始化
	mpz_t p_Ef;mpz_init(p_Ef);
	mpz_t q_Ef;mpz_init(q_Ef);
	 
	
	//GMP函数应用 生成一个随机数 
	clock_t time = clock();//设定时钟函数 
	gmp_randstate_t grt;//GMP函数应用 生成一个随机数 
	gmp_randinit_default(grt);//使用默认的算法初始化状态，速度和随机性的折中 
	gmp_randseed_ui(grt,time);//初始种子设置到state 
	mpz_urandomb(p,grt,50);//生成一个范围为0到2^n-1（含）的均匀分布的随机整数，赋值到p
	
	//p、q生成 
	while(!mpz_cmp_ui(p,100000000000000))//对p和 大数比较，大于时返回正数，即小于时陷入循环生成 
	{
		mpz_urandomb(p,grt,50);
	}
	mpz_nextprime(p,p);
	
	mpz_urandomb(q,grt,50);
	while(!mpz_cmp_ui(q,100000000000000))//对p和 大数比较，大于时返回正数，即小于时陷入循环生成 
	{
		mpz_urandomb(q,grt,50);
	}
	mpz_nextprime(q,q);
	
	mpz_mul(N,p,q);//GMP乘法n=p*q 
	mpz_sub_ui(p_Ef,p,1);//GMP减法计算p、q的欧拉值 
	mpz_sub_ui(q_Ef,q,1);
	mpz_mul(N_Ef,p_Ef,q_Ef);//GMP乘法计算N的欧拉值N_f=(p-1)*(q-1) 
	
	gmp_printf("p_Ef（欧拉值） = %Zd\n",p_Ef);
	gmp_printf("q_Ef（欧拉值）= %Zd\n",q_Ef);
	gmp_printf("N_Ef（欧拉值） = %Zd\n",N_Ef);
	gmp_printf("素数p = %Zd\n",p);
	gmp_printf("素数q = %Zd\n",q);
	gmp_printf("模数N = %Zd\n",N);
	gmp_printf("公钥E = %Zd\n",E);

	mpz_invert(D,E,N_Ef);//GMP逆元函数 满足D*E（modN_f）=1 
	mpz_urandomb(M,grt,90);
	while(!mpz_cmp(M,N)){
		mpz_urandomb(p,grt,90);
	}	
	gmp_printf("密钥D = %Zd\n",D);
	gmp_printf("十进制明文M = %Zd\n",M);
	gmp_printf("十六进制明文M = %Zx\n",M);
	
	return 0;
}

//
int En_RSA(char E_bi[],mpz_t E,mpz_t C,mpz_t M,mpz_t N){
	mpz_get_str(E_bi,2,E);//将公钥E以2进制存入E_bi数组 
	mpz_init_set_str(C,"1",10);//初始化C为10进制的1 
	int E_len=strlen(E_bi);//数组长度 
	for(int i=0;i<E_len;i++){
		mpz_mul(C,C,C);//C平方处理 
		mpz_mod(C,C,N);//C=CmodN 
		if('1'==E_bi[i])// 
		{
			mpz_mul(C,C,M);//C=C*M 
			mpz_mod(C,C,N);//C=CmodN 
		}		
	}
	return 0;
}

// 
int De_RSA(char D_bin[],mpz_t D,mpz_t C,mpz_t M,mpz_t N){
	mpz_get_str(D_bin,2,D);
	mpz_init_set_str(M,"1",10);
	int d_len=strlen(D_bin);
	for(int i=0;i<d_len;i++){
		mpz_mul(M,M,M);
		mpz_mod(M,M,N);
		if('1'==D_bin[i]){
			mpz_mul(M,C,M);	
			mpz_mod(M,M,N);
		}
	}
	return 0;
}

//测试数据函数（实验数据） 
void test(mpz_t N,mpz_t M,mpz_t E,mpz_t C,mpz_t p,mpz_t q,mpz_t D)
{
	mpz_t s_N;mpz_t s_M;mpz_t s_E;mpz_t s_D;//定义并初始化
	mpz_init(s_N);mpz_init(s_M);mpz_init(s_E);mpz_init(s_D);
	long int N_trans=0,M_trans=0,E_trans=0,D_trans=0;//定义长整型N、M、E、D 
	fp_plain=fopen("rsa_plain.txt","rw+");
	fscanf(fp_plain,"%s",plain_arr);
	fp_pubkey=fopen("rsa_pubkey.txt","rw+");
	fscanf(fp_pubkey,"%s",N_arr);
	fscanf(fp_pubkey,"%s",E_arr);
	fp_prikey=fopen("rsa_prikey.txt","rw+");
	fscanf(fp_prikey,"%s",N_arr);
	fscanf(fp_prikey,"%s",D_arr);
	int plain_len=strlen(plain_arr);
	for(int i=0;i<plain_len;i++)
	{
		M_trans = c2i(plain_arr[i]);
		mpz_set_si(s_M,M_trans);
		mpz_mul_si(M,M,16);
		mpz_add(M,M,s_M);
	}
	int N_len=strlen(N_arr);
	for(int i=0;i<N_len;i++)
	{
		N_trans = c2i(N_arr[i]);
		mpz_set_si(s_N,N_trans);
		mpz_mul_si(N,N,16);
		mpz_add(N,N,s_N);
	}
	int D_len=strlen(D_arr);
	for(int i=0;i<D_len;i++){
		D_trans = c2i(D_arr[i]);
		mpz_set_si(s_D,D_trans);
		mpz_mul_si(D,D,16);
		mpz_add(D,D,s_D);
	}		
	gmp_printf("N = %Zd\n",N);
	gmp_printf("E = %Zd\n",E);
	gmp_printf("D = %Zd\n",D);
	gmp_printf("M = %Zd\n",M);
	En_RSA(E_bi,E,C,M,N);
	printf("加密生成密文：");
	gmp_printf("C = %Zx\n",C);
	fp_cipher=fopen("rsa_cipher.txt","rw+");
	mpz_out_str(fp_cipher,16,C);
	fprintf(fp_cipher,"\n");
	fclose(fp_cipher);
	De_RSA(D_bi,D,C,M,N);
	printf("解密生成明文：");
	gmp_printf("M = %Zx\n",M);
	En_RSA(D_bi,D,C,M,N);
	printf("加密生成数字签名：");
	gmp_printf("C = %Zx\n",C);
}
//随机测试 
void test_random(mpz_t p,mpz_t q,mpz_t N,mpz_t E,mpz_t D,mpz_t M,mpz_t C)
{
	random(p,q,N,E,D,M);
	fp_p=fopen("p.txt","rw+");
	mpz_out_str(fp_p,16,p);
	fclose(fp_p);
	fp_q=fopen("q.txt","rw+");
	mpz_out_str(fp_q,16,q);
	fclose(fp_q);
	fp_e=fopen("e.txt","rw+");
	mpz_out_str(fp_e,16,E);
	fclose(fp_e);
	fp_d=fopen("d.txt","rw+");
	mpz_out_str(fp_d,16,D);
	fclose(fp_d);
	fp_m=fopen("m.txt","rw+");
	mpz_out_str(fp_m,16,M);
	fclose(fp_m);
	fp_n=fopen("n.txt","rw+");
	mpz_out_str(fp_n,16,N);
	fclose(fp_n);
	En_RSA(E_bi,E,C,M,N);
	printf("加密生成密文：");
	gmp_printf("C = %Zx\n",C);
	De_RSA(D_bi,D,C,M,N);
	fp_cipher=fopen("rsa_cipher.txt","rw+");
	mpz_out_str(fp_cipher,16,C);
	fclose(fp_cipher);
	printf("解密生成明文：");
	gmp_printf("M = %Zx\n",M);
	En_RSA(D_bi,D,C,M,N);
	printf("加密生成数字签名：");
	gmp_printf("C = %Zx\n",C);
	fp_sign=fopen("rsa_sign.txt","rw+");
	mpz_out_str(fp_sign,16,C);
	fclose(fp_sign);	
} 
//主函数 
int main(int argc, const char *argv[]){
	mpz_t N;mpz_t M;mpz_t E;mpz_t C;mpz_t p;mpz_t q;mpz_t D;//定义并初始化函数所使用的n、p、q、e、d，同时定义明文M和密文C 
	mpz_init(N);mpz_init(M);mpz_init(E);mpz_init(C);mpz_init(p);mpz_init(q);mpz_init(D); 
	
	mpz_init_set_str(N,"0",10);//定义N为十进制0 
	mpz_init_set_str(C,"1",10);//定义C为十进制1 
	mpz_init_set_str(E,"65537",10);//定义E为十进制65537
	 
	printf("		RSA实验（@NING）\n\n");
	printf("实验选项：\n\n");
	printf("1.测试实验数据（RSA实验数据）\n\n");
	printf("2.随机生成一组RSA加密数据\n\n");
	printf("q.无操作退出\n\n");
	printf("（Please enter your choice）");
	fflush(stdin);
	char choice = getchar();
	while(choice!='1'&&choice!='2'&&choice!='q'){
		printf("输入错误，系统自动退出");
		fflush(stdin);
		choice = getchar();
	}
	switch(choice){
		case '1':{
			test(N,M,E,C,p,q,D); 
			break;
		}
		case '2':{
			test_random(p,q,N,E,D,M,C); 
			break;

	}
		case 'q':
			return 0;
		default: printf("错误，退出！！");	
	}
	return 0;
}
