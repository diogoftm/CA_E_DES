#pragma once

#include <openssl/conf.h>

int opensslSetup(
    const char *configFilePath = "../openssl.conf")
{
    if (!CONF_modules_load_file(configFilePath, NULL, 0))
    {
        fprintf(stderr, "Error loading OpenSSL configuration file.\n");
        return EXIT_FAILURE;
    }

    OPENSSL_init_crypto(0, NULL);
    return EXIT_SUCCESS;
}
