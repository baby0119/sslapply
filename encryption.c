#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/**
* 功能描述:3DES加密
* @param pData：原始数据
* @param ilen: 原始数据长度
* @param ppDecryptData: 加密后数据
* @return -1: 失败, 其他: 加密数据长度
**/
int TripleDESEncrypt(const char* pData, int ilen, char** ppEncodeData)
{
    /*密钥*/
    unsigned char key[24] = {43,14,54,109,109,8,84,87,116,30,19,68,35,51,83,72,16,2,83,48,117,85,9,80};
    /*初始化向量*/
    unsigned char iv[8] = {111,121,47,42,75,34,33,124};

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    int rc = EVP_EncryptInit_ex(&ctx,EVP_des_ede3_cbc(),NULL,key,iv);
    if (rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }

    /*对齐方式*/
    int datalen = (ilen%8) == 0 ? (ilen + 8) : ((8 - ilen%8) + ilen);
    *ppEncodeData = (char*)malloc(datalen);
    memset(*ppEncodeData, 0, datalen);

    int outlen = 0;
    rc = EVP_EncryptUpdate(&ctx, (unsigned char*)(*ppEncodeData), &outlen, (unsigned char*)pData, ilen);
    if(rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        free(*ppEncodeData);
        return -1;
    }
    int outlentmp = 0;
    rc = EVP_EncryptFinal_ex(&ctx, (unsigned char*)(*ppEncodeData) + outlen,&outlentmp);
    if(rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        free(*ppEncodeData);
        return -1;
    }
    outlen += outlentmp;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return outlen;
}

/**
* 功能描述:3DES解密
* @param pData：原始数据
* @param ilen: 原始数据长度
* @param ppDecryptData: 解密后数据
* @return -1: 失败, 其他: 解密数据长度
**/
int TripleDESDecrypt(const char* pData, int ilen, char** ppDecryptData)
{
    /*密钥*/
    unsigned char key[24] = {43,14,54,109,109,8,84,87,116,30,19,68,35,51,83,72,16,2,83,48,117,85,9,80};
    /*初始化向量*/
    unsigned char iv[8] = {111,121,47,42,75,34,33,124};

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    int rc = EVP_EncryptInit_ex(&ctx,EVP_des_ede3_cbc(),NULL,key,iv);
    if (rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }

    int outlen = ilen + 1;
    *ppDecryptData = (char*)malloc(outlen);
    memset(*ppDecryptData, 0 , outlen);

    rc = EVP_DecryptUpdate(&ctx, (unsigned char*)(*ppDecryptData), &outlen, (unsigned char*)pData, ilen);
    if(rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        free(*ppDecryptData);
        return -1;
    }
    int outlentmp = 0;
    rc = EVP_DecryptFinal_ex(&ctx, (unsigned char*)(*ppDecryptData) + outlen,&outlentmp);
    if(rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        free(*ppDecryptData);
        return -1;
    }
    outlen += outlentmp;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return outlen;
}

/**
* 功能描述:RSA加密
* @param pData：原始数据
* @param ilen: 原始数据长度
* @param pEncodeData: 加密后数据
* @return -1: 失败, 其他: 加密数据长度
**/
int RSAEncrypt(const char* pData , int iLen, char** pEncodeData)
{
    char chPublicKey[] = "-----BEGIN PUBLIC KEY-----\n"
                         "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCb/vAGucNg3OJyBV6/aWEd7IK9"
                         "46GYnOT089mDzNY2zDBB9hPWwdSUYOTbDROlc3Gd4eOudeQqlnAgHB7zqwVGqWuG"
                         "vbqHWSSPpp6pMilpVVz9SMbL/1BgfhK+dKWIDYHJDRJFpBLFUpe0vq8n+8Mdgp1z"
                         "NPH3cR+rWK8zI5xF5wIDAQAB"
                         "\n-----END PUBLIC KEY-----\n";


    BIO *bio = BIO_new_mem_buf(chPublicKey, -1);
    if (!bio)
    {
        return -1;
    }
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa)
    {
        return -1;
    }
    int nLen = RSA_size(rsa);
    char* pEncode = (char*)malloc(nLen + 1);
    int rc = RSA_public_encrypt(iLen, (const unsigned char*)pData, (unsigned char*)pEncode, rsa, RSA_PKCS1_PADDING);
    *pEncodeData = pEncode;
    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();
    return rc;
}

/**
* 功能描述:RSA解密
* @param pData：原始数据
* @param ilen: 原始数据长度
* @param pEncodeData: 加密后数据
* @return -1: 失败, 其他: 加密数据长度
**/
int RSADecrypt(const char* pData , int iLen, char** pDecodeData)
{
    char chPrivateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
                          "MIICXQIBAAKBgQCb/vAGucNg3OJyBV6/aWEd7IK946GYnOT089mDzNY2zDBB9hPW\n"
                          "wdSUYOTbDROlc3Gd4eOudeQqlnAgHB7zqwVGqWuGvbqHWSSPpp6pMilpVVz9SMbL\n"
                          "/1BgfhK+dKWIDYHJDRJFpBLFUpe0vq8n+8Mdgp1zNPH3cR+rWK8zI5xF5wIDAQAB\n"
                          "AoGBAJesW+KeMbp3afElCYegxV2b/U72CcPiILeOdRoySsHC7NTll0qC8ddHEp1t\n"
                          "bIG86mZxILgbRjqmROTjkrCmwxv5tHT1LRHz139BPQHbOx+Dx5Q/D9wUzGKSr/Df\n"
                          "lUsORpqmQjVsgLtCzIZShXr/O2rf8FU6zbtI3f6UQK1wMcxRAkEAydNkWUvSkxC2\n"
                          "40fA8+6mYFXEWgJpXLcaMX+CqMmE+h/xwDJ7qB0dbqdPA64Pq2jgLAFWlSxF4QWk\n"
                          "Kp19gaoR/wJBAMXeT0LqCg7RG365KsvXzJVf9gzxN1X0ahhKBSoAS66UgpyVDGcl\n"
                          "b+NchCepqev6Li/U+Zteg/UrTTNBN8S3fBkCQHyGhX/jHIXI5k7NUuwu71C5GnE+\n"
                          "06t0/iBUQFXMINQDKbIgc9OCQ0qmyEXI+7oS912vZbCcpHD2fhgdG/cI7BkCQQCK\n"
                          "gIxWuGAF8xUd5RsxyIJp5NvkP0yOnCFPkzB+L+rJ7yZl2GbwJGJncbEH2lkY1uxR\n"
                          "ivCVctlHWeIWCIay6gSxAkAF19y/R2dMkop5Pl0UkGCzY4Bgqqmnxs+I+o2Z4EwE\n"
                          "xc/l6vH6yP3DmelxC4abDk/N7bgaU99lQ2iwN+RpHUpP"
                          "\n-----END RSA PRIVATE KEY-----\n";
    BIO *bio = BIO_new_mem_buf(chPrivateKey, -1);
    if (!bio)
    {
        return -1;
    }
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!rsa)
    {
        return -1;
    }

    int nLen = RSA_size(rsa);
    char* pDecode = (char*)malloc(nLen + 1);
    memset(pDecode, 0, nLen+1);
    int rc = RSA_private_decrypt(nLen ,(unsigned char *)pData,(unsigned char*)pDecode,rsa,RSA_PKCS1_PADDING);
    *pDecodeData = pDecode;
    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();
    return rc;
}

