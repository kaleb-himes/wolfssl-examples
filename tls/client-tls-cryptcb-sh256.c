/* client-tls.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define DEFAULT_PORT 11111

#define CERT_FILE "../certs/ca-cert.pem"

void error_out(char* msg, int err);
int KALEBTEST_deviceCb(int devId, wc_CryptoInfo* info, void* userContext);
int KALEB_fake_hardware_call(char* out, char* in, int inSz);


int main(int argc, char** argv)
{
    int                sockfd;
    struct sockaddr_in servAddr;
    char               buff[256];
    size_t             len;
    int                ret;
    int devId = 1;
    char* CbNote = "made it into the callback";

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;



    /* Check for proper calling convention */
    if (argc != 2) {
        printf("usage: %s <IPv4 address>\n", argv[0]);
        return 0;
    }

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        goto end;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1;
        goto end;
    }

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
         == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto end;
    }

    /*---------------------------------*/
    /* Start of security */
    /*---------------------------------*/
    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto socket_cleanup;
    }

/* register a devID for crypto callbacks */
    ret = wc_CryptoCb_RegisterDevice(devId, KALEBTEST_deviceCb, CbNote);
    if (ret != 0)
        error_out("wc_CryptoCb_RegisterDevice", ret);

    wolfSSL_CTX_SetDevId(ctx, devId);
/* register a devID for crypto callbacks */


    /* Load client certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL))
         != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        goto ctx_cleanup;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        goto ctx_cleanup;
    }

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }

    /* Connect to wolfSSL on the server side */
    if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        goto cleanup;
    }

    /* Get a message for the server from stdin */
    printf("Message for server: ");
    memset(buff, 0, sizeof(buff));
    if (fgets(buff, sizeof(buff), stdin) == NULL) {
        fprintf(stderr, "ERROR: failed to get message for server\n");
        ret = -1;
        goto cleanup;
    }
    len = strnlen(buff, sizeof(buff));

    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, buff, len)) != len) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
        goto cleanup;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if ((ret = wolfSSL_read(ssl, buff, sizeof(buff)-1)) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        goto cleanup;
    }

    /* Print to stdout any data the server sends */
    printf("Server: %s\n", buff);

    /* Cleanup and return */
cleanup:
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
ctx_cleanup:
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
socket_cleanup:
    close(sockfd);          /* Close the connection to the server       */
end:
    return ret;               /* Return reporting a success               */
}

void error_out(char* msg, int err)
{
    printf("Failed at %s with code %d\n", msg, err);
    exit(1);
}

int KALEBTEST_deviceCb(int devId, wc_CryptoInfo* info, void* userContext)
{
    int ret = -1;
    wc_Sha256 sha256;

    printf("%s\n", (char*) userContext);

    if (devId == 1) {
        /* Using device with ID == 1 */
        /* check for which type of algo we're doing, types are:
         *   WC_ALGO_TYPE_NONE = 0,
         *   WC_ALGO_TYPE_HASH = 1,
         *   WC_ALGO_TYPE_CIPHER = 2,
         *   WC_ALGO_TYPE_PK = 3,
         *   WC_ALGO_TYPE_RNG = 4,
         *   WC_ALGO_TYPE_SEED = 5,
         *   WC_ALGO_TYPE_HMAC = 6,
         *   WC_ALGO_TYPE_MAX = WC_ALGO_TYPE_HMAC
         */

        if (info->algo_type == WC_ALGO_TYPE_HASH) {
            printf("OK, doing a hash on device 1. What kind of hash is it?\n");
            /* check for which type of hash we're doing, types are:
             *      WC_HASH_TYPE_NONE = 15
             *      WC_HASH_TYPE_MD2 = 16
             *      WC_HASH_TYPE_MD4 = 17
             *      WC_HASH_TYPE_MD5 = 0
             *      WC_HASH_TYPE_SHA = 1
             *      WC_HASH_TYPE_SHA224 = 8
             *      WC_HASH_TYPE_SHA256 = 2
             *      WC_HASH_TYPE_SHA384 = 5
             *      WC_HASH_TYPE_SHA512 = 4
             *      WC_HASH_TYPE_MD5_SHA = 18
             *      WC_HASH_TYPE_SHA3_224 = 10
             *      WC_HASH_TYPE_SHA3_256 = 11
             *      WC_HASH_TYPE_SHA3_384 = 12
             *      WC_HASH_TYPE_SHA3_512 = 13
             *      WC_HASH_TYPE_BLAKE2B = 14
             *      WC_HASH_TYPE_BLAKE2S = 19
             *      WC_HASH_TYPE_MAX = WC_HASH_TYPE_BLAKE2S
             */
            if (info->hash.type == WC_HASH_TYPE_SHA256) {
                if (info->hash.sha256 == NULL) {
                    printf("The sha256 structure was not initialized\n");
                    ret = wc_InitSha256(&sha256);
                    if (ret != 0)
                        return CRYPTOCB_UNAVAILABLE;
                    info->hash.sha256 = &sha256;
                }
                /* Here is where the hardware would be invoked to compute the
                 * hash of the provided info, we're going to fake it:
                 * parameters are:
                 * info->hash.sha256 (the wolfSSL sha256 structure.)
                 *   the hardware computes the hash and updates sha256->digest
                 * info->hash.in (the message passed in to be hashed)
                 * info->hash.inSz (the size of the message)
                 */
                KALEB_fake_hardware_call((char*) info->hash.sha256->digest,
                                         (char*) info->hash.in,
                                         info->hash.inSz);
                printf("Hash computed by the hardware was %s\n",
                       (char*) info->hash.sha256->digest);
            } else {
                printf("Whoops, hash type not supported on this device: %d\n",
                       info->hash.type);
            };
        }
    } else if (devId == 2) {
        /* Using device with ID == 2 */
    } else {
        printf("Whoops, support for this device hasn't been added: %d\n", devId);
        ret = CRYPTOCB_UNAVAILABLE;
    }
    return ret;
}

int KALEB_fake_hardware_call(char* out, char* in, int inSz)
{
    int i;

    /* In theory here we would have passed the "in" to the hardware, the
     * hardware would perform a sha256 init and a series of sha256 update calls
     * until the hash of the entire message had been computed. The result would
     * then be placed in the output buffer which was the sha256->digest buffer
     */

    for (i = 0; i < WC_SHA256_DIGEST_SIZE; i++)
        out[i] = 'K';
    out[i] = '\0'; /* string terminator for the sake of printing %s on return
                    * in this example */
    return 0; /* fake success */
}

