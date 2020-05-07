#!/usr/bin/env python

# Реализация Unpadded Message Recovery Oracle
from prob33 import mypow
from prob39 import generatePrime, invmod

# Это оказывается тривиально разрушаемым:
def generate_rsa_key(bits, e=65537):
    result = { "e" : e }
    p = (e+1)
    q = (e+1)
    while ((p % e) == 1):
        p = generatePrime(bits//2);
    while ((q%e) == 1):
        q = generatePrime(bits//2);
    result["p"] = p;
    result["q"] = q;
    result["N"] = p*q;
    result["d"] = invmod(e, (p-1)*(q-1));
    return result;


# * Захват зашифрованного текста C
def capture_ciphertext(message, modulus, e):
    return mypow(message, e, modulus);

def decrypt_cipher(cipher, rsaparams):
    return mypow(cipher, rsaparams['d'], rsaparams['N'])

# * Пусть N и E - открытый модуль и показатель соответственно

# * Пусть S будет случайным числом> 1 мод N. Неважно, что.

# * C '= ((S ** E mod N) * C) mod N

# * Отправить C ', который выглядит совершенно иначе, чем C, на сервер,
# восстанавливающий P ', который выглядит совершенно отличным от P

#         П'
# P = ----- mod N
# S

# Упс!

# (Мы не просто делим мод N; мы умножаем на
# мультипликативный обратный мод N.)

# Осуществляем эту атаку.
def do_unpadded_rsa_attack():
    rsaparams = generate_rsa_key(2048);
    e = rsaparams['e']
    N = rsaparams['N']
    messageBytes = b'Oh captain my captain'
    messageInt = int.from_bytes(messageBytes, byteorder="big")
    print('messageInt is     :  %d' % messageInt)
    capturedCipher = capture_ciphertext(messageInt, N, e);
    S = 8675309
    C_prime = (mypow(S, e, N) * capturedCipher) % N;
    P_prime = decrypt_cipher(C_prime, rsaparams);
    plain = (P_prime * invmod(S, N)) % N;
    print('recover message is :',plain)
    assert(plain == messageInt);
    
if __name__ == "__main__":
    do_unpadded_rsa_attack();
    print("Success");
    