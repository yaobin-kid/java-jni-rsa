#include <jni.h>
#include <string>
#include "RSAOSUtil.h"
#include "BASE64Util.h"

/*
 * Class:     RASUtils
 * Method:    encryptJNI 公钥加密
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 */
extern "C" JNIEXPORT jstring JNICALL Java_com_aiks_util_RSAUtils_encryptJNI(JNIEnv *env, jobject instance, jstring _data, jstring _publicKey){
	const char *data = env->GetStringUTFChars(_data, 0);
	const char *publicKey = env->GetStringUTFChars(_publicKey, 0);
	std::string key;
	key.assign(publicKey);   
	std::string datamsg;
	datamsg.assign(data);
    std::string rsa = RSAOSUtil::encryptRSAbyPublickey(datamsg, NULL,key);
    rsa = BASE64Util::base64_encodestring(rsa);
    return env->NewStringUTF(rsa.c_str());
  }
  
  /*
 * Class:     RASUtils
 * Method:    encryptJNI 私钥解密数据
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 */
  extern "C" JNIEXPORT jstring JNICALL Java_com_aiks_util_RSAUtils_decryptJNI(JNIEnv *env, jobject instance, jstring _data, jstring _privateKey){
	const char *data = env->GetStringUTFChars(_data, 0);
	const char *privateKey = env->GetStringUTFChars(_privateKey, 0);
	std::string key;
	key.assign(privateKey);
	std::string datamsg;
	datamsg.assign(data);
    std::string rsa = BASE64Util::base64_decodestring(datamsg);
    rsa = RSAOSUtil::decryptRSAbyPrivateKey(rsa,key);
    return env->NewStringUTF(rsa.c_str());
  }
  
    /**
     * 私钥加密
     */
extern "C" JNIEXPORT jstring JNICALL Java_com_aiks_util_RSAUtils_encryptJNIPri(JNIEnv *env, jobject instance, jstring _data, jstring _privateKey){
	const char *data = env->GetStringUTFChars(_data, 0);
	const char *privateKey = env->GetStringUTFChars(_privateKey, 0);
	std::string key;
	key.assign(privateKey);
	std::string datamsg;
	datamsg.assign(data);
	
	
	std::string rsa = RSAOSUtil::encryptRSAbyPrivateKey(datamsg, NULL,key);
    rsa = BASE64Util::base64_encodestring(rsa);

    return env->NewStringUTF(rsa.c_str());
	
}



/**
*公钥解密
**/
extern "C" JNIEXPORT jstring JNICALL Java_com_aiks_util_RSAUtils_decryptJNIPub(JNIEnv *env, jobject, jstring _data, jstring _publicKey){
	  const char *data = env->GetStringUTFChars(_data, 0);
	const char *publicKey = env->GetStringUTFChars(_publicKey, 0);
	std::string key;
	key.assign(publicKey);
	std::string datamsg;
	datamsg.assign(data);
	
	std::string rsa = BASE64Util::base64_decodestring(datamsg);
    rsa = RSAOSUtil::decryptRSAbyPublicKey(rsa,key);

    return env->NewStringUTF(rsa.c_str());
}