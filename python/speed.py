from tqdm import tqdm
from dataclasses import dataclass
import time
from Crypto.Cipher import DES
import random
import EDES

key = bytearray([random.randint(0, 255) for _ in range(32)])
plaintext = bytearray([random.randint(0, 255) for _ in range(4096)])
tries = 1000

@dataclass
class Statistics:
    lowest_time_ns: int

def test_DES() -> Statistics:
    fastest_time = -1

    cipher = DES.new(key[:8], DES.MODE_ECB)


    for _ in tqdm(range(tries), desc="Testing DES"):
        t1 = time.monotonic_ns()
        ciphertext = cipher.encrypt(plaintext)
        t2 = time.monotonic_ns()
        if fastest_time == -1 or (t2 - t1) < fastest_time:
            fastest_time = t2 - t1
    return Statistics(fastest_time)

def test_EDES() -> Statistics:
    fastest_time = -1

    cipher = EDES.EDES()
    cipher.set_key(key)
    for _ in tqdm(range(tries), desc="Testing EDES"):
        t1 = time.monotonic_ns()
        cipher.encrypt(plaintext)
        t2 = time.monotonic_ns()
        if fastest_time == -1 or (t2 - t1) < fastest_time:
            fastest_time = t2 - t1
    return Statistics(fastest_time)

def main():
    s_des = test_DES()
    s_edes = test_EDES()
    fast_factor = s_des.lowest_time_ns / s_edes.lowest_time_ns
    print(f"EDES was {fast_factor} times faster than DES\n")

if __name__ == '__main__':
    main()