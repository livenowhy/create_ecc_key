/************************************************************************/
/* <加密卡相关的全局函数声明>                                                 */
/************************************************************************/
#include "swsds.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>


/**
 * 保存数据到文件
 * filename:保存的文件名
 * mode:保存时用的文件格式
 * buffer:需要保存数据的指针
 * size:buffer的数据长度，必须传入，buffer可能没有数据结束标志
 */
int FileWrite(char *filename, char *mode, unsigned char *buffer, size_t size);

int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size);

/**
 * 保存公钥数据和私钥数据到文件
 * filename_public:保存公钥数据的文件
 * filename_private:保存私钥数据的文件
 *
 */
int save_key_pair_ecc(char *filename_public, char *filename_private, ECCrefPublicKey *p_public_key, ECCrefPrivateKey *p_private_key);

/**
 * 标准错误码定义
 * 根据错误码输出错误信息，并且打印调用函数传入的msg信息
 */
int print_error_msg(int ret, char *msg);

/**
 * 功能：以二进制的形式打印sourceData中的内容
 * itemName打印的名称，dataLength为sourceData指针指向数据的长度，rowCount一行打印十六进制的个数
 * 当rowCount = dataLength时只打印一行；rowCount = 1时，打印dataLength行
 */
int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount);

void Bcd2Bin(const char *bufBCD, unsigned int nBYTELen, unsigned char *bufBIN);

int Bin2BcdAndSave(void *buf_bin, unsigned int bin_len, char *file_name);  // 把二进制数据保存为十六进制格式

int read_bcd_key_to_bin(void *buf_bin, unsigned int bcd_len, char *bcd_file_name);//读取以十六进制格式保存的秘钥
