import unittest
from Crypto.Hash import SHA256
from EDES import EDES

class TestEDES(unittest.TestCase):
    def setUp(self):

        key = bytearray([(i * 137) % 256 for i in range(32)])
        self.edes = EDES()
        self.edes.set_key(key)

    def test_encryption(self):
        plaintext = bytearray([(i * 139) % 256 for i in range(64)])
        ciphertext = self.edes.encrypt(plaintext)
        self.assertNotEqual(plaintext, ciphertext)

    def test_decryption(self):
        plaintext = bytearray([(i * 131) % 256 for i in range(64)])
        ciphertext = self.edes.encrypt(plaintext)
        decrypted_text = self.edes.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_text)

if __name__ == '__main__':
    unittest.main()