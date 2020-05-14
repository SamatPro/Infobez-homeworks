import base64
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.misc import modexp
from util.rsa import make_rsa_keys, rsa
from util.text import to_bytes, to_str

PTEXT_B64 = b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="


def make_oracle(privkey):
    def oracle(ctext):
        return not rsa(ctext, privkey, as_bytes=False) & 1

    return oracle


def decryptor(ctext, pubkey, oracle, show=True):
    e, n = pubkey
    two = modexp(2, e, n)


    lower, upper, bit_length = 0, 1, n.bit_length()

    for i in range(1, bit_length + 1):
        diff, lower, upper = upper - lower, lower << 1, upper << 1
        ctext = (ctext * two) % n
        if oracle(ctext):
            upper -= diff
        else:
            lower += diff
        print("\r" + to_str((upper * n) >> i) + "\033[K", end="", flush=True)
    else:
        print()

    return to_bytes((upper * n) >> bit_length)


def main():
    print("Generating an RSA key pair, please wait.")

    pubkey, privkey = make_rsa_keys(bits=1024)
    oracle = make_oracle(privkey)

    print("Generating and decrypting ciphertext.")
    print()

    ctext = rsa(base64.b64decode(PTEXT_B64), pubkey, as_bytes=False)

    decryptor(ctext, pubkey, oracle)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
