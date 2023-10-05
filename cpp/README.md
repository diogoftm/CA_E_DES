# E-DES C++ implementation
## Files
- EDES.h - header file for the E-DES library.
- EDES.cpp - E-DES library implementation.
- encrypt.cpp - encryption application for E-DES and DES (openssl), ECB mode and PKCS#7 padding.
- deprypt.cpp - decryption application for E-DES and DES (openssl), ECB mode and PKCS#7 padding.
- speed.cpp - application to evaluate the relative performance of E-DES and DES (openssl).
- test_edes.cpp - E-DES unit tests using Google Test.

## Compile and execute
### Encrypt application

Compilation and example usage:
``` bash
make encrypt
./encrypt pswd123 "My plaintext"
```

Optionally the '-s' can be added to the end of the command in order to use the standard DES:

``` bash
./encrypt pswd123 "My plaintext" -s
```

### Decrypt application

Compilation and example usage:
``` bash
make decrypt
./decrypt pswd123 qYWaMoZeRsOQc16JRnGnJQ==
```

Optionally the '-s' can be added to the end of the command in order to use the standard DES:

``` bash
./decrypt pswd123 Q+1tlWJ9fS9BYH00dC2+qQ== -s
```

### Unit tests

Compilation and usage:
``` bash
make test_edes
./test_edes
```

