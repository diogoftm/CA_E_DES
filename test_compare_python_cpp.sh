#!/bin/bash

edes_pw="it_works"
expected_output="CA_EDES_TEST_COMPAREpythonAndCpp1"
expected_output2="14242h42h4h51"

cpp_output=$(echo "$expected_output" | ./cpp/encrypt $edes_pw)
python_output=$(echo "$cpp_output" | python3 python/decrypt.py $edes_pw)

if [ "$python_output" = "$expected_output" ]; then
    echo "cpp encryption and python decryption test passed!"
else
    echo "cpp encryption and python decryption test failed! x"
    exit 1
fi

python_output2=$(echo "$expected_output2" | python3 python/encrypt.py $edes_pw)
cpp_output2=$(echo "$python_output2" | ./cpp/decrypt $edes_pw)



if [ "$cpp_output2" = "$expected_output2" ]; then
    echo "python encryption and cpp decryption test passed!"
    exit 0
else
    echo "python encryption and cpp decryption test failed! x"
    exit 1
fi





