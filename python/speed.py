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
    avg_time_ns: int
    highest_time_ns: int


def test_DES() -> Statistics:
    fastest_time = -1
    avg_time_ns = 0
    highest_time = -1

    cipher = DES.new(key[:8], DES.MODE_ECB)

    for _ in tqdm(range(tries), desc="Testing DES"):
        t1 = time.monotonic_ns()
        ciphertext = cipher.encrypt(plaintext)
        t2 = time.monotonic_ns()
        if fastest_time == -1 or (t2 - t1) < fastest_time:
            fastest_time = t2 - t1

        if highest_time == -1 or (t2 - t1) > highest_time:
            highest_time = t2 - t1

        avg_time_ns += t2 - t1

    avg_time_ns //= tries

    return Statistics(fastest_time, avg_time_ns, highest_time)


def test_EDES() -> Statistics:
    fastest_time = -1
    highest_time = -1
    avg_time = 0

    cipher = EDES.EDES()
    cipher.set_key(key)
    for _ in tqdm(range(tries), desc="Testing EDES"):
        t1 = time.monotonic_ns()
        cipher.encrypt(plaintext)
        t2 = time.monotonic_ns()
        if fastest_time == -1 or (t2 - t1) < fastest_time:
            fastest_time = t2 - t1

        if highest_time == -1 or (t2 - t1) > highest_time:
            highest_time = t2 - t1

        avg_time += t2 - t1

    avg_time //= tries

    return Statistics(fastest_time, avg_time, highest_time)


def printStatisticsComparison(stats1, stats2):

    print(f"Statistics Comparison between DES and EDES [{tries} test cases]:")
    print(f"DES - Lowest Time: {stats1.lowest_time_ns} ns")
    print(f"EDES - Lowest Time: {stats2.lowest_time_ns} ns")
    print()

    print(f"DES - Highest Time: {stats1.highest_time_ns} ns")
    print(f"EDES - Highest Time: {stats2.highest_time_ns} ns")
    print()

    print(f"DES - Average Time: {stats1.avg_time_ns} ns")
    print(f"EDES - Average Time: {stats2.avg_time_ns} ns")


def main():
    s_des = test_DES()
    s_edes = test_EDES()

    printStatisticsComparison(s_des, s_edes)


if __name__ == '__main__':
    main()
