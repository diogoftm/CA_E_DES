#include <openssl/conf.h>
#include <unistd.h>
#include <cstring>
#include <libgen.h>

#define MIN(A,B) A < B ? A : B

int opensslSetup(const char *configFilePath = "openssl.conf")
{
    char pBuf[256];
    size_t len = sizeof(pBuf);
    int bytes = MIN(readlink("/proc/self/exe", pBuf, len), len - 1);
    if (bytes >= 0) {
        pBuf[bytes] = '\0';
    }

    char* dirName = dirname(pBuf);

    size_t dirLen = strlen(dirName);
    size_t pathLen = dirLen + 1 + strlen(configFilePath);
    char fullPath[pathLen + 1];

    strcpy(fullPath, dirName);
    fullPath[dirLen] = '/';
    strcpy(fullPath + dirLen + 1, configFilePath);

    int ecode;
    if ((ecode = CONF_modules_load_file(fullPath, NULL, 0)) <= 0)
    {
        fprintf(stderr, "Error loading OpenSSL configuration file.\nLoad SSL config exited with code %d\n", ecode);
        exit(EXIT_FAILURE);
    }

    OPENSSL_init_crypto(0, NULL);
    return EXIT_SUCCESS;
}