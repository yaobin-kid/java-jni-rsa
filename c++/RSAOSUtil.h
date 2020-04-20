//
// Created by iotimc on 2019/10/25.
//

#ifndef ENCRYPTDEMO_MYRSA_H
#define ENCRYPTDEMO_MYRSA_H

#include <string>

class RSAOSUtil{
public:
	//公钥加密
    static std::string encryptRSAbyPublickey(const std::string& data,int *lenreturn,std::string publicKey);
	//私钥解密
    static std::string decryptRSAbyPrivateKey(const std::string& data,std::string privateKey);
	//私钥加密
	static std::string encryptRSAbyPrivateKey(const std::string& data,int *lenreturn,std::string privateKey);
	//公钥解密
	static std::string decryptRSAbyPublicKey(const std::string& data,std::string publicKey);
};

#endif //ENCRYPTDEMO_MYRSA_H
