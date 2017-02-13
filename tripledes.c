#include <stdlib.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

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
    *ppDecryptData = new char[outlen];
    memset(*ppDecryptData, 0 , outlen);

    rc = EVP_DecryptUpdate(&ctx, (unsigned char*)(*ppDecryptData), &outlen, (unsigned char*)pData, ilen);
    if(rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        delete[] *ppDecryptData;
        return -1;
    }

    int outlentmp = 0;
    rc = EVP_DecryptFinal_ex(&ctx, (unsigned char*)(*ppDecryptData) + outlen,&outlentmp);
    if(rc != 1)
    {
        HCSDK_ERROR_LOG("EVP_DecryptFinal_ex fail %d", rc);
        EVP_CIPHER_CTX_cleanup(&ctx);
        delete[] *ppDecryptData;
        return -1;
    }
    outlen += outlentmp;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return outlen;
}

/*3DES解密*/
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
    *ppDecryptData = new char[outlen];
    memset(*ppDecryptData, 0 , outlen);

    rc = EVP_DecryptUpdate(&ctx, (unsigned char*)(*ppDecryptData), &outlen, (unsigned char*)pData, ilen);
    if(rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        delete[] *ppDecryptData;
        return -1;
    }

    HCSDK_INFO_LOG("outlen %d", outlen);
    int outlentmp = 0;
    rc = EVP_DecryptFinal_ex(&ctx, (unsigned char*)(*ppDecryptData) + outlen,&outlentmp);
    if(rc != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        delete[] *ppDecryptData;
        return -1;
    }
    outlen += outlentmp;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return outlen;
}
