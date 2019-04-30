#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/rsa.h>

int main(void)
{
    int ret = -1;
#ifdef OPENSSL_EXTRA
    WOLFSSL_X509* x509cert;
    WOLFSSL_EVP_PKEY* pubKeyTmp;
    RsaKey pubKey;
    char* certFName = "../../certs/client-cert.pem";
    word32 idx = 0;
    int i;

    (void) idx;

    x509cert = wolfSSL_X509_load_certificate_file(certFName, WOLFSSL_FILETYPE_PEM);
    if (x509cert == NULL) {
        printf("Failed to load cert, abort!\n");
        return ret;
    }
    printf("Loaded cert successfully\n");

    pubKeyTmp = wolfSSL_X509_get_pubkey(x509cert);
    if (pubKeyTmp == NULL) {
        printf("Failed to extract public key, abort!\n");
        return ret;
    }
    printf("Extracted public key successfully\n");

    /* setup a key structure to receive the extracted key */
    wc_InitRsaKey(&pubKey, 0);
    ret = wc_RsaPublicKeyDecode((byte*)pubKeyTmp->pkey.ptr, &idx, &pubKey,
                                 (word32) pubKeyTmp->pkey_sz);
    if (ret != 0) {
        printf("Failed to decode public key from pubKeyTmp, abort!\n");
        return ret;
    }
    printf("Succesfully decoded public key\n");

    printf("PUBLIC KEY:\n");
    for (i = 0; i < pubKeyTmp->pkey_sz; i++) {
        printf("%02X", pubKeyTmp->pkey.ptr[i] & 0xFF);
    } printf("\n");


    wolfSSL_EVP_PKEY_free(pubKeyTmp);
    wolfSSL_X509_free(x509cert);
    wc_FreeRsaKey(&pubKey);
#else
    printf("Please configure wolfssl with --enable-opensslextra to try using\n"
           "this example\n");
#endif
    return ret;
}
