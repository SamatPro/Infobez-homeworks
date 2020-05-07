#!/usr/bin/env python

# Реализация RSA


from Crypto.Util.number import getPrime


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

def mypow(a, b, c): # returns a^b mod c
    # b = 0, 1 are special cases:
    if (b == 0):
        return 1 # thus, 0**0 = 1
    if (b == 1):
        return (a % c)
    b_bits = bin(b)[2:] # 2 strips off the leading 0b
    res = a;
    for i in range(1, len(b_bits)):     # ignore the first '1'
        # square
        res = res * res;
        # multiply?
        if (b_bits[i] == '1' ):
            res = res * a;
        # mod
        res = res % c;
    return res;


rawToHexLUT = ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f',
               '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f',
               '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f',
               '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f',
               '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f',
               '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f',
               '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f',
               '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f',
               '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f',
               '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f',
               'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af',
               'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf',
               'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf',
               'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df',
               'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef',
               'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff',]

# hex to raw
def hexToRaw(hx):
    raw = binascii.unhexlify(hx);
    return raw;

# raw to hex
def rawToHex(raw):
    #hx = binascii.hexlify(raw);
    hx = '';
    for r in raw:
        if type(r) != int:
            r = ord(r);
        hx += rawToHexLUT[r];
    return bytes(hx, 'UTF-8');
    
    
if __name__ == "__main__":
    rsa_demo1();
    rsa_demo2();
    print("Success!!!");
