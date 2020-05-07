#!/usr/bin/env python

# Реализация RSA


from Crypto.Util.number import getPrime
from prob33 import mypow
from prob1 import rawToHex, hexToRaw

def generatePrime(bits):
    return getPrime(bits);
    


'''#Рекурсивный метод

Возвращает (x,y) которые (ax + by) = gcd(a,b)'''
def egcd(a, b):
    if b == 0:
        return (1, 0)
    else:
        q = a // b;
        r = a % b;
        (s, t) = egcd(b, r)
        return (t, s - q * t)

# возвращает a^-1 mod N
def invmod(a, N):
    # ax + by = 1:
    # ax - 1 = by
    # ax - 1 = 0 mod b
    # ax = 1 mod b
    # x является обратной к mod b
    (x, y) = egcd(a, N);
    return x % N;

# - Генерирует 2 случайные простые числа

def rsa_demo1():
    p = 71;
    q = 77;
    N = p*q;

    et = (p-1)*(q-1);
    e = 3;
    assert((et%e) != 0);

    d = invmod(e,et)

    message = 42;
    encrypted = mypow(message, e, N);
    decrypted = mypow(encrypted, d, N);
    print('p = %d;q = %d; N = %d; e=%d; d=%d; message = %d; encrypted=%d' % (p,q,N,e,d,message,encrypted));
    assert(message == decrypted);
    

#Повторяет с простыми числами (оставляет е = 3).
def rsa_demo2():
    e = 3;
    p = 4;
    q = 4;
    while ((p % e) == 1):
        p = generatePrime(1024);
    while ((q % e) == 1):
        q = generatePrime(1024);
    N = p*q;
    phi = (p-1)*(q-1);
    assert((phi%e) != 0);
    d = invmod(e, phi);
    message = 42;
    encrypted = mypow(message, e, N);
    decrypted = mypow(encrypted, d, N);
    print('p = %d;q = %d; N = %d; e=%d; d=%d; message = %d; encrypted=%d'% (p,q,N,e,d,message,encrypted));
    assert(message == decrypted);
# Наконец, чтобы зашифровать строку, конвертируем
# строка в гекс и поставить "0x" на передней части, чтобы превратить его в
#число.
    rawMessage = b'May the Force be with you'
    hexMessage = rawToHex(rawMessage);
    intMessage = int(hexMessage, 16);
    encrypted = mypow(intMessage, e, N);
    decrypted = mypow(encrypted, d, N);
    assert(intMessage == decrypted);
    assert(hexToRaw(hex(intMessage)[2:]) == rawMessage);
    
    
if __name__ == "__main__":
    rsa_demo1();
    rsa_demo2();
    print("Success!!!");
