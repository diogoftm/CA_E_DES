from Crypto.Hash import SHA256


# To do:
# - adicionar geração das sboxs
# - verificar tipagem pois creio que não esteja 100% correta

# Class to handle the creation of the sboxs for E-DES
class SBOXESGenerator:
    @staticmethod
    def generate(key):
        derivedKey = SBOXESGenerator.generate_derived_key(key)

        sboxes = [ [0 for _ in range(0,256)] for _ in range(0, 16)]
        shuffled_arr = [i for i in range(0,4096)]

        for i in range(0, 4095):

            j = ((int(derivedKey[2*(i+1)-1]) << 8) + int(derivedKey[2*i])) % 4096

            vj = shuffled_arr[j]
            vi = shuffled_arr[i]

            shuffled_arr[j] = vi
            shuffled_arr[i] = vj

        currval = 0
        curriter = 0

        for i in range(0,4096):
            pos = shuffled_arr[i]
            sboxes[int(pos / 256)][pos % 256] = currval

            curriter += 1
            if curriter >= 16:
                curriter = 0
                currval += 1

        return sboxes


    @staticmethod
    def generate_derived_key(key: bytes):
        
        niter = 8192 // 32
        result = b''
        for i in range(niter):
            h = SHA256.new()
            h.update(key)
            
            if i != 0:
                h.update(result[-32:])

            result += h.digest()

        return result

        


# E-DES implementation
class EDES:
    def __init__(self):
        self.set_key([0x00] * 32)
    
    # f function
    @staticmethod
    def __f(val : bytes , sbox : bytes):
        assert len(val) == 4 , "Invalid input size. len(input)!=4 bytes"
        index = val[3]
        out : bytes = []
        out.append(sbox[index])
        index = (index + val[2]) % 256
        out.append(sbox[index])
        index = (index + val[1]) % 256
        out.append(sbox[index])
        index = (index + val[0]) % 256
        out.append(sbox[index])
        return out
    
    # Feistel Network (encryption)
    @staticmethod
    def __fN(val : bytes , sbox : bytes):
        assert len(val) == 8 , "Invalid input size for Feistel Network. Condition: len(input)==8 bytes"
        l : bytes = val[:4]
        r : bytes = val[4:]

        rf : bytes = EDES.__f(r, sbox)

        result : bytes = [0] * 8
        for i in range(0, 4):
            result[i + 4] = l[i] ^ rf[i]
            result[i] = r[i]

        return result
    
    # Reversed Feistel Network (decryption)
    @staticmethod
    def __fNR(val : bytes , sbox : bytes):
        assert len(val) == 8 , "Invalid input size for Feistel Network. Condition: len(input)!=8 bytes"
        l : bytes = val[:4]
        r : bytes = val[4:]

        lf : bytes = EDES.__f(l, sbox)

        result : bytes = [0] * 8
        for i in range(0, 4):
            result[i] = r[i] ^ lf[i]
            result[i + 4] = l[i]

        return result
    
    # Process a full 64 bit block
    def __processBlock(self, block : bytes, reverseFlag : bool):
        assert len(block) == 8 , "Invalid block size. Condition: len(block)!=8 bytes"
        result = block
        for i in range(0, 16):
            if not reverseFlag:
                result = EDES.__fN(result, self.sboxes[i])
            else:
                result = EDES.__fNR(result, self.sboxes[15 - i])
        return result
    

    ####################
    #  Public methods  #
    ####################


    # Set 256 bit key
    # To do:
    def set_key(self, key : bytes):
        assert len(key) == 32 , "Invalid key size. Condition: len(key) == 32 bytes"
        
        self.key = key
        self.sboxes = SBOXESGenerator.generate(key)

    # Encrypt all blocks
    def encrypt(self, plaintext : bytes):
        assert  len(plaintext) % 8 == 0, "Invalid plaintext size. Condition: len(data)%8 == 0"
        plain_len : int = len(plaintext)
        result : bytes = [0] * plain_len
        for i in range(0, plain_len, 8):
            block = plaintext[i : i+8]
            r = self.__processBlock(block, 0)
            result[i : i+8] = r
        return bytes(result)
    
    # Encrypt all blocks
    def decrypt(self, plaintext : bytes):
        assert  len(plaintext) % 8 == 0, "Invalid plaintext size. Condition: len(data)%8 == 0"
        plain_len : int = len(plaintext)
        result : bytes = [0] * plain_len
        for i in range(0, plain_len, 8):
            block = plaintext[i : i+8]
            r = self.__processBlock(block, 1)
            result[i : i+8] = r
        return bytes(result)

    
