
#include "swsdsglobalfun.h"
#include <stdio.h>
#include <string.h>


int print_error_msg(int ret, char *msg);

#define   INPUT_SRGV_ILLEGAL -1

int main(int argc, char **argv)
{
	if(argc <= 3 || atoi(argv[1]) <= 0 || atoi(argv[1]) >= 3)
	{
		printf("输入参数不合法./a.out <算法标识1 or 2 or 3> <需要产生密钥长度>");
		return INPUT_SRGV_ILLEGAL;
	}

	int temp;


	printf("%d %d \n", atoi(argv[1]), atoi(argv[2]));

	unsigned int alg_id; //指定算法标识
	switch(atoi(argv[1]))
	{

	case 1:
		alg_id = SGD_SM2_1;
		break;
	case 2:
		alg_id = SGD_SM2_2;
		break;
	case 3:
		alg_id = SGD_SM2_3;
		break;
	}

	unsigned int key_bits; //指定密钥长度
	key_bits = atoi(argv[2]);

	SGD_HANDLE hDeviceHandle; // 设备句柄

	int ret;
	if(SDR_OK != (ret = SDF_OpenDevice(&hDeviceHandle)))
	{
		print_error_msg(ret, "Open Device Error");
		return 0;
	}

	SGD_HANDLE hSessionHandle;
	if(SDR_OK != (ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle)))
	{
		print_error_msg(ret, "Open Session Error");
		return 0;
	}

	ECCrefPublicKey public_key; // ECC 公钥结构
	ECCrefPrivateKey private_key; // ECC 私钥结构

	if(SDR_OK != (ret = SDF_GenerateKeyPair_ECC(hSessionHandle, alg_id, key_bits, &public_key, &private_key)))
	{
		print_error_msg(ret, "Generate Key Pair ECC Error");
		return 0;
	}

	PrintData("public_key", &public_key, sizeof(ECCrefPublicKey), 32);
	PrintData("private_key", &private_key, sizeof(ECCrefPrivateKey), 32);

	Bin2BcdAndSave(&public_key, sizeof(ECCrefPublicKey), "PublicKey.txt");
	Bin2BcdAndSave(&private_key, sizeof(ECCrefPrivateKey), "PrivateKey.txt");


	int index;
	char *filename_public = "public.key";
	char *filename_private = "private.key";

	save_key_pair_ecc(filename_public, filename_private, &public_key, &private_key);

	ECCrefPublicKey public_key_r;   // ECC 公钥结构
	ECCrefPrivateKey private_key_r; // ECC 私钥结构

	int puk_len, prk_len;

// 	puk_len = FileRead(filename_public, "rb", (unsigned char *)&public_key_r, sizeof(public_key_r));
// 	if(puk_len < sizeof(ECCrefPublicKey))
// 	{
// 		printf("读取公钥失败，按任意键退出................\n");
// 		return 0;
// 	}

	read_bcd_key_to_bin("PublicKey.txt", (unsigned char*)&public_key_r, sizeof(ECCrefPublicKey));
	read_bcd_key_to_bin("PrivateKey.txt", (unsigned char*)&private_key_r, sizeof(ECCrefPrivateKey));
	//read_bcd_key_to_bin(&public_key_r, sizeof(ECCrefPublicKey), filename_public);

// 	prk_len = FileRead(filename_private, "rb", (unsigned char *)&private_key_r, sizeof(private_key_r));
// 	if(prk_len < sizeof(ECCrefPrivateKey))
// 	{
// 		printf("读取私钥失败，按任意键退出................\n");
// 		return 0;
// 	}

// 	unsigned char *tmp = (unsigned char *)&private_key;
// 	for (index = 0; index < sizeof(private_key); index++)
// 	{
// 		printf("%02x", *(tmp + index));
// 	}
// 	printf("========================================\n");
// 
// 	unsigned char key_read_buf[1024];
// 	unsigned char key_bin_buf[1024];
// 	memset(key_read_buf, 0, sizeof(key_read_buf));
// 	memset(key_bin_buf, 0, sizeof(key_bin_buf));
// 
// 	FILE *fp_read = NULL;
// 	if((fp_read = fopen("PrivateKey.txt", "rb")) == NULL)
// 	{
// 		printf("file open failed!");
// 		return 0;
// 	}
// 
// 	ret = fread(&key_read_buf, 1, 2 * sizeof(ECCrefPrivateKey), fp_read);
// 	perror("222");
// 
// 	int n_len = strlen(key_read_buf) / 2;
// 
// 	printf("%d   \n", n_len);
// 	if(n_len <= 0)
// 		return -1;
// 	Bcd2Bin(key_read_buf, n_len, key_bin_buf);
// 	memcpy(&private_key_r, key_bin_buf, sizeof(ECCrefPrivateKey));
// 
// 	printf("---------------------------------------\n");
// 
// 	tmp = (unsigned char *)&private_key_r;
// 	for (index = 0; index < sizeof(ECCrefPrivateKey); index++)
// 	{
// 		printf("%02x", *(tmp + index));
// 	}
// 	printf("========================================\n");







	char *data_buf = "qwertyuioplkjhgfdsazxcvbnm123423523656788?><:}{+_)(*&^%$#@!";
	int data_len = strlen(data_buf);
	ECCCipher out_data;

	printf("encypt ---> %s \n", data_buf);

	if(SDR_OK != (ret = SDF_ExternalEncrypt_ECC(hSessionHandle, alg_id, &public_key_r, data_buf, data_len, &out_data)))
	{
		print_error_msg(ret, "Encrypt Error");
		return ret;
	}
	char data_dec[1024] = {0};
	int data_dec_len;
	if(SDR_OK != (ret = SDF_ExternalDecrypt_ECC(hSessionHandle, alg_id, &private_key_r, &out_data, &data_dec, &data_dec_len)))
	{
		print_error_msg(ret, "Decrypt Error");
		return ret;
	}


	printf("  data ---> %s  \n", data_dec);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);
	return 0;
}
