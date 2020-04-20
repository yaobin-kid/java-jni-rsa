package com.aiks.util;

/**
 * @author 深圳市埃克思科技有限公司
 * @date 2020/4/20
 * @description
 */
public class RSAUtils {
    //公钥
    public static final String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZGpeLJIAZZEvd4eHuIwDof1gZH+g8gCw7gxaI5UiXQBCzlPjGRPuRndB4dS+fUuU39Xxp35MaWj+vSS/b0TbvfyZRzan5CIdy9bzehDUuqjpshGQbB68vY1z2nuj6GYvYwm4OcyODNao1WBqexR5ob5eE77b7ERJATrW/z6qXuQIDAQAB";
    //私钥
    public static final String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANkal4skgBlkS93h4e4jAOh/WBkf6DyALDuDFojlSJdAELOU+MZE+5Gd0Hh1L59S5Tf1fGnfkxpaP69JL9vRNu9/JlHNqfkIh3L1vN6ENS6qOmyEZBsHry9jXPae6PoZi9jCbg5zI4M1qjVYGp7FHmhvl4TvtvsREkBOtb/Pqpe5AgMBAAECgYEAg4YXnsT7EebwCzin3dO43iEfpwDseZKQuXD9+uskofS+6XxrhfoOibYYsJEVy6i1ksQWnjFC9ekMwc1NwBar9yfkQaV0eqLGEVnlz9n6A/7OX+zYZ83fxfylG3nm+M8chNzGX/xrK8RwpeG2+S+XFFK4xrUHWNrX2tQ5NgtZ9n0CQQDr0Y6EnpbZbiDK8VOn3wlMiFh6IIjrxn93S3i/55b9mfFA6l2Rb4h+FCdb2TC58JevqISZlYGBgB1oKXvv19ObAkEA668F7rPVbNvLZn0ML+U30irrbhGH8gNrxZfe/tKiraBJi0FwyN8LJHMMCs8zLw9HYq8Ma8hJ4KedxvjvlyspOwJADJ57JOejpOD6ykFdu6b4xWqqaWaiTROjMIwOWx6Wet2pBlNETIsOX8jOTmDx9ZFFXLYE2n8gngBwEmnd4vjGrwJBAMtRZSPEvhS4FGNo8w+KhbpoTkvZEdclPl7qonRgj/iK84cPwFV5nSonmbblgrlRS/sFGgkNczY8Q294J3DYyisCQQCecBfqR4E82WocNQ/vNKhZqmJS3srjeNtkPWO1AORsXbhUDiwSpgC6rM+ugn69luNwqjaslqRHKbzKOeoMkzth";

    static {
       // System.load("/root/rsa/libtest.so");
        System.load("/usr/local/rsa/librsa.so");
    }

    /**
     * 公钥加密
     */
    public native String encryptJNI(String encryptTextData, String publicKey);

    /***
     * 私钥解密
     * ***/
    public native String decryptJNI(String decryptTextData, String privateKey);

    /**
     * 私钥加密
     */
    public native String encryptJNIPri(String encryptTextData, String privateKey);

    /***
     * 公钥解密
     * **/
    public native String decryptJNIPub(String decryptTextData, String publicKey);

    public static void main(String[] args) {
        RSAUtils ras = new RSAUtils();
        String encrypt = ras.encryptJNI("123", publicKey);
        System.out.println("java public key encrypt:" + encrypt);
        System.out.println("java private key decrypt:" + ras.decryptJNI(encrypt, privateKey));
        System.out.println("--------------------------");
        String privateEncrypt = ras.encryptJNIPri("abcd", privateKey);
        System.out.println("java private key encrypt:" + privateEncrypt);
        System.out.println("java public key decrypt:" + ras.decryptJNIPub(privateEncrypt, publicKey));
    }
}
