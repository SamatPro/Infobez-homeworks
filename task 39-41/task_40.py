#!/usr/bin/env python

# Реализует E=3 RSA Broadcast attack
# импортируем из 39 таска
from task_39 import egcd, invmod, generatePrime
from task_39 import mypow


def do_CRT(a_list, N_list):
    assert(len(a_list) >= 3);
    assert(len(N_list) >= 3);
    x = 0;
    N = N_list[0] * N_list[1] * N_list[2];
    for i in range(3):
        (r,s) = egcd(N_list[i], N//N_list[i]);
        e = s*N//N_list[i];
        x += a_list[i] * e;
    return (x % N);

def do_rsa_broadcast_attack(pubkeys, messages):
    result = do_CRT(messages, pubkeys);
    return pow(result, 1/3.0);


def generateModulus(size, e):
    p = e+1;
    q = e+1;
    while ((p%e) == 1):
        p = generatePrime(size//2);
    while ((q%e) == 1):
        q = generatePrime(size//2);
    return p*q;

if __name__ == "__main__":

    assert(do_CRT((2,3,2), (3,5,7)) == 23);
    assert(do_CRT((2,3,1), (3,4,5)) == 11);
    data = 0x040815162342

    pubkeys = [generateModulus(1024, 3), generateModulus(1024, 3), generateModulus(1024, 3)];
    print(pubkeys);
    messages = [mypow(data, 3, N) for N in pubkeys];
    recovered = do_rsa_broadcast_attack(pubkeys, messages);
    print(data)
    print(round(recovered));
    
