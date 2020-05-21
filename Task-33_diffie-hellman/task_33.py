from hashlib import sha256
from symbol import assert_stmt


def smallDHDemo():
    p = 37;
    g = 5;

    a = getOneRandomByte() % p;
    A = pow(g, a, p)

    b = getOneRandomByte() % p
    B = pow(g, b, p)

    s_b = pow(B, a, p)

    s_a = pow(A, b, p)

    print(s_a, s_b)
    assert (s_a == s_b)
    # Чтобы превратить «s» в ключ, вы можете просто хэшировать его для создания 128 битов
    # ключ материала (или SHA256 это для создания ключа для шифрования и ключа
    # для MAC).
    encKey, macKey = secretToKeys(intToBytes(s_a))


def intToBytes(integer):
    hex_form = hex(integer)[2:];  # 2: gets rid of leading 0x
    if (len(hex_form) % 2):
        hex_form = '0' + hex_form;
    return bytearray.fromhex(hex_form)


# generate choice
def getOneRandomByte():
    byte = RAND_bytes(1);
    return byte[0];

def secretToKeys(secret):
    hashoutput = sha256(secret).digest()
    encKey = hashoutput[0:16];
    macKey = hashoutput[16:32];
    return encKey, macKey;




group5_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
group5_g = 2;


def mypow(a, b, c):  # returns a^b mod c
    # b = 0, 1 are special cases:
    if (b == 0):
        return 1  # thus, 0**0 = 1
    if (b == 1):
        return (a % c)
    b_bits = bin(b)[2:]  # 2 strips off the leading 0b
    res = a;
    for i in range(1, len(b_bits)):  # ignore the first '1'
        # square
        res = res * res;
        # multiply?
        if (b_bits[i] == '1'):
            res = res * a;
        # mod
        res = res % c;
    return res;


def testMyPow():
    test_b = [0, 1, 5, 65537, pow(2, 32) - 1, pow(2, 32) + 1, pow(2, 256) + pow(2, 64) + pow(2, 16) + 1]

    for b in test_b:
        theirs = pow(group5_g, b, group5_p);
        mine = mypow(group5_g, b, group5_p);
        assert (mine == theirs);


if __name__ == "__main__":
    smallDHDemo();
    testMyPow();
    # if here, asserts passed
    print("problem 33 success");