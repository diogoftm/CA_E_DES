# E-DES
> Applied Cryptography 1st project
> 
> Authors: Diogo Matos (102848), Tiago Silvestre (103554)

## Goal
Data Encryption Standard (DES) was developed in the early 70's and was considered secure and became quite popular. It uses a 56 bit key and block sizes of 64 bits performing 
16 round of Feistel Networks and permutations in the beginning and at the end. The secrecy behind the S-Boxes used inside the Feistel Networks led to concerns of possible
hiden trapdoors and, most importantly, the key size has been too small for more than two decades. Another
aspect that is not desirable is how slow the DES is compared to its competition.

In this project we introduce a new cipher called Enhanced Data Encryption Standard (E-DES) that mainly aims to twist DES in order to be more secure and faster. 
E-DES uses a 256 bit key, maintains the block size, removes both permutation boxes, doesn't use sub-keys and the creation of the S-Boxs depends only on the key.

## Directory structure

- /cpp - C++ E-DES implementation and test apps.
- /python - Python E-DES implementation and test apps.
- /report - Report pdf and source files.

## Test

Read README.md file inside the implementation directory (/cpp, /python).
