//
// Created by iotimc on 2019/10/25.
//
#include "RSAOSUtil.h"
#include <iostream>
#include <memory.h>
#include <stdio.h>
#include "BASE64Util.h"
using namespace std; 
extern "C" {
#include "/usr/include/openssl/bio.h"
#include "/usr/include/openssl/evp.h"
#include "/usr/include/openssl/rsa.h"
#include "/usr/include/openssl/pem.h"
}
 
#define  PADDING   RSA_PKCS1_PADDING          //填充方式
/**
 * 注意注意：不能用一种秘钥同时做加密解密。只能公钥加密+私钥解密 / 私钥加密+公钥解密
 *
 * 公钥存在客户端，私钥存在服务端
 * */

/**
 * 公钥加密
 * */
std::string RSAOSUtil::encryptRSAbyPublickey(const std::string &data, int *lenreturn,std::string strPublicKey) {
    int nPublicKeyLen = strPublicKey.size(); //strPublicKey为base64编码的公钥字符串
    for (int i = 64; i < nPublicKeyLen; i += 64) {
        if (strPublicKey[i] != '\n') {
            strPublicKey.insert(i, "\n");
        }
        i++;
    }
    strPublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
    strPublicKey.append("\n-----END PUBLIC KEY-----\n");


    BIO *bio = NULL;
    RSA *rsa = NULL;
    char *chPublicKey = const_cast<char *>(strPublicKey.c_str());
    if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
    {
        //LOGE("BIO_new_mem_buf failed!\n");
		std::cout<<"BIO_new_mem_buf failed!"<<endl;
    }

    rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (rsa == NULL){
       // LOGE("rsa == NULL");
	   	std::cout<<"rsa == NULL!"<<endl;
    } else{
       // LOGE("rsa != NULL");
	   	std::cout<<"rsa != NULL"<<endl;
    }
    int flen = RSA_size(rsa);


    std::string strRet;
    strRet.clear();

    char *encryptedText = (char *) malloc(flen + 1);
    memset(encryptedText, 0, flen + 1);

    // 加密函数
    //rsa加密算法是有限制的。受到密钥长度限制。你应该把要加密的内容分块。一块块加密。这样可以避免长度限制问题
    int ret = RSA_public_encrypt(data.length(), (const unsigned char *) data.c_str(), (unsigned char *) encryptedText,
                                 rsa, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        strRet = std::string(encryptedText, ret);
    }

    RSA_free(rsa);
    BIO_free_all(bio);

    free(encryptedText);

    //CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return strRet;
}

/***
	私钥解密
**/
std::string RSAOSUtil::decryptRSAbyPrivateKey(const std::string &data,std::string strPrivateKey) {
    int nPrivateKeyLen = strPrivateKey.size(); //strPublicKey为base64编码的公钥字符串
    for(int i = 64; i < nPrivateKeyLen; i+=64)
    {
        if(strPrivateKey[i] != '\n')
        {
            strPrivateKey.insert(i, "\n");
        }
        i++;
    }
    strPrivateKey.insert(0, "-----BEGIN PRIVATE KEY-----\n");
    strPrivateKey.append("\n-----END PRIVATE KEY-----\n");

    int flen;
    BIO *bio = NULL;
    RSA *r = NULL;
    char *chPrivateKey = const_cast<char *>(strPrivateKey.c_str());
    if ((bio = BIO_new_mem_buf((void *) chPrivateKey, -1)) == NULL)       //从字符串读取RSA公钥
    {
        //LOGE("BIO_new_mem_buf failed!\n");
		cout<<"BIO_new_mem_buf failed!"<<endl;
    }

    r = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    flen = RSA_size(r);

    static std::string gkbn;
    gkbn.clear();

    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);

    int status = RSA_private_decrypt(data.length(), (unsigned char *) data.c_str(),
                                     (unsigned char *) dst, r, PADDING);//RSA_NO_PADDING //RSA_PKCS1_PADDING
    if (status < 0) {
		cout<<"RSA decrypt FAILED-->"<<status<<endl;
        //LOGE("RSA 私钥解密失败--->%d", status);
        return "";

    }

    gkbn.assign((char *) dst, status);//防止 尾部0 被截断

    BIO_free_all(bio);

    free(dst);

    // CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;
}






/**
 * 私钥加密
 * */
std::string RSAOSUtil::encryptRSAbyPrivateKey(const std::string &data, int *lenreturn,std::string strPrivateKey) {
	//cout<<"privateKey:"<<strPrivateKey<<endl;
	//cout<<"data:"<<data<<endl;

    int nPrivateKeyLen = strPrivateKey.size(); //strPublicKey为base64编码的公钥字符串
    for (int i = 64; i < nPrivateKeyLen; i += 64) {
        if (strPrivateKey[i] != '\n') {
            strPrivateKey.insert(i, "\n");
        }
        i++;
    }
    strPrivateKey.insert(0, "-----BEGIN PRIVATE KEY-----\n");
    strPrivateKey.append("\n-----END PRIVATE KEY-----\n");

    int ret, flen;
    BIO *bio = NULL;
    RSA *r = NULL;
    char *chPrivateKey = const_cast<char *>(strPrivateKey.c_str());
    if ((bio = BIO_new_mem_buf((void *) chPrivateKey, -1)) == NULL)       //从字符串读取RSA公钥
    {
        //LOGE("BIO_new_mem_buf failed!\n");
		 	std::cout<<"BIO_new_mem_buf failed!"<<endl;
    }

    r = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (r == NULL){
       //LOGE("r == NULL");
		 	std::cout<<"r == NULL"<<endl;
    } else{
        //LOGE("r != NULL");
		 	std::cout<<"rsa != NULL"<<endl;
    }
    flen = RSA_size(r);

    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
//        flen -= 11;
    }

    lenreturn = &flen;

    static std::string gkbn;
    gkbn.clear();

    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);

    int status = RSA_private_encrypt(data.length(), (unsigned char *) data.c_str(),
                                     (unsigned char *) dst, r, RSA_PKCS1_PADDING);

    if (status < 0) {

        //LOGE("RSA 私钥加密失败--->%d", status);
		std::cout<<"RSA 私钥加密失败--->"<<status<<endl;
        return "";

    }

    gkbn.assign((char *) dst, status);

    RSA_free(r);
    BIO_free_all(bio);

    free(dst);

    //CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;
}



/**
 * 公钥解密
 * */
std::string RSAOSUtil::decryptRSAbyPublicKey(const std::string &data,std::string strPublicKey) {

    int nPublicKeyLen = strPublicKey.size(); //strPublicKey为base64编码的公钥字符串
    for(int i = 64; i < nPublicKeyLen; i+=64)
    {
        if(strPublicKey[i] != '\n')
        {
            strPublicKey.insert(i, "\n");
        }
        i++;
    }
    strPublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
    strPublicKey.append("\n-----END PUBLIC KEY-----\n");


    int ret, flen;
    BIO *bio = NULL;
    RSA *r = NULL;
    //LOGE("RSA 公钥解密开始--->%d", 1);
	cout<<"RSA 公钥解密开始--->1"<<endl;
    char *chPublicKey = const_cast<char *>(strPublicKey.c_str());
    if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
    {
       // LOGE("BIO_new_mem_buf failed!\n");
		cout<<"BIO_new_mem_buf failed!"<<endl;
    }
    //LOGE("RSA 公钥解密开始--->%d", 2);
    r = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    flen = RSA_size(r);
    //LOGE("RSA 公钥解密开始--->%d", 3);
    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
//        flen -= 11;
    }
    //LOGE("RSA 公钥解密开始--->%d", 4);
	
    static std::string gkbn;
    gkbn.clear();
    //LOGE("RSA 公钥解密开始--->%d", 5);
	cout<<"RSA 公钥解密开始--->5"<<endl;
    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);
    //LOGE("RSA 公钥解密开始--->%d", 6);
	cout<<"RSA 公钥解密开始--->6"<<endl;
    int status = RSA_public_decrypt(data.length(), (unsigned char *) data.c_str(),
                                    (unsigned char *) dst, r, RSA_PKCS1_PADDING);//RSA_NO_PADDING //RSA_PKCS1_PADDING
    if (status < 0) {
        //LOGE("RSA 公钥解密失败--->%d", status);
		cout<<"RSA 公钥解密失败--->"<<status<<endl;
        return "";

    }

    gkbn.assign((char *) dst, status);//防止 尾部0 被截断

    BIO_free_all(bio);

    free(dst);

    // CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;

}




