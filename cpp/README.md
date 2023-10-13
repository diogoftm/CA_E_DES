# E-DES C++ implementation
## Files
- EDES.h - header file for the E-DES library.
- EDES.cpp - E-DES library implementation.
- encrypt.cpp - encryption application for E-DES and DES (openssl), ECB mode and PKCS#7 padding.
- deprypt.cpp - decryption application for E-DES and DES (openssl), ECB mode and PKCS#7 padding.
- speed.cpp - application to evaluate the relative performance of E-DES and DES (openssl).
- test_edes.cpp - E-DES unit tests using Google Test.


## Requirements
[OpenSSL](https://www.openssl.org/) is necessary for calling DES and SHA256.
[googletest](https://github.com/google/googletest) is required for compiling tests.

In Debian-based distributions, the following commands are sufficient to install the dependencies:
```
apt-get install libssl-dev
apt-get install libgtest-dev
```


## Compile and execute
### Encrypt application

Compilation and example usage:
``` bash
make encrypt
echo "My plaintext" | ./encrypt pswd123
```

Optionally the '-s' can be added to the end of the command in order to use the standard DES:

``` bash
echo "My plaintext" | ./encrypt pswd123 "My plaintext" -s
```

*Note*: When using running it using the input from the keyboard, you can type and change line as you like, to submit just press ctrl+d .

### Decrypt application

Compilation and example usage:
``` bash
make decrypt
echo "qYWaMoZeRsOQc16JRnGnJQ==" | ./decrypt pswd123
```

Optionally the '-s' can be added to the end of the command in order to use the standard DES:

``` bash
echo "qYWaMoZeRsOQc16JRnGnJQ==" | ./decrypt pswd123 -s
```

### Unit tests

Compilation and usage:
``` bash
make test_edes
./test_edes
```

