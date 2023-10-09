# E-DES Python implementation
## Files
- EDES.py - E-DES library implementation.
- encrypt.py - encryption application for E-DES and DES (pycryptodome), ECB mode and PKCS#7 padding.
- deprypt.py - decryption application for E-DES and DES (pycryptodome), ECB mode and PKCS#7 padding.
- speed.py - application to evaluate the relative performance of E-DES and DES (pycryptodome).
- test_edes.py - E-DES unit tests.

## Compile and execute
### Encrypt application

Usage example:
``` bash
echo "My plaintext" | python3 encrypt.py pswd123
```

Optionally the '-s' can be added to the end of the command in order to use the standard DES:

``` bash
echo "My plaintext" | python3 encrypt.py pswd123 -s
```

*Note*: When using running it using the input from the keyboard, you can type and change line as you like, to submit just press ctrl+d .

### Decrypt application

Usage example:
``` bash
echo "qYWaMoZeRsOQc16JRnGnJQ==" | python3 decrypt.py pswd123
```

Optionally the '-s' can be added to the end of the command in order to use the standard DES:

``` bash
echo "qYWaMoZeRsOQc16JRnGnJQ==" | python3 decrypt.py pswd123 -s
```

### Unit tests

Usage:
``` bash
python3 test_edes.py
```

