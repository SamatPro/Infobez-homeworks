#!/usr/bin/env python3
#
# Bleichenbacher's e=3 RSA Attack
#
#
import inspect
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(lambda: 0)))))

from util.misc import nth_root
from util.rsa import make_rsa_keys, rsa
from util.sha1 import SHA1
from util.text import byte_length, from_bytes, to_bytes

ASN_1 = bytes.fromhex("003021300906052B0E03021A05000414")


def sign_rsa(bs, privkey, hash_cls=SHA1):
    # Хеш, подвергнутый RSA "расшифровке", дополняется до
    # той же длины, что и модуль RSA в соответствии с PKCS # 1.5.
    phash = ASN_1 + hash_cls(bs).digest()
    phash = b"\x00\x01" + phash.rjust(byte_length(privkey[1]) - 2, b"\xff")
    return rsa(phash, privkey)


def verify_rsa(bs, sig, pubkey, hash_cls=SHA1):
    phash = rsa(sig, pubkey)

    # Сбить ведущий 0x01, хотя бы один 0xff и магию ASN.1.
    # ПРИМЕЧАНИЕ: rsa () уже сбивает ведущий 0x00.
    if phash.startswith(b"\x01\xff"):
        phash = phash[1:]
        while phash[0] == 0xFF:
            phash = phash[1:]
        if phash.startswith(ASN_1):
            phash = phash[len(ASN_1) :]

    return phash.startswith(hash_cls(bs).digest())


def forge_rsa_e3(bs, pubkey, hash_cls=SHA1):
    e, n = pubkey
    n_byte_length = byte_length(n)

    # Создание дополненного хэша, который начинается с "0x0001ff00 <ASN.1> <ptext_digest>",
    # заканчивается практически чем угодно, и имеет такой же размер, как и модуль.
    phash = b"\x00\x01\xff" + ASN_1 + hash_cls(bs).digest()
    phash = phash.ljust(n_byte_length, b"\xff")

    # Найти целое число от корня этого хэша; это не должно быть идеально.
    eth_root = nth_root(from_bytes(phash), e)
    forged_sig = to_bytes(eth_root)

    # Окончательная поддельная подпись корректна по праву и равна модулю.
    return forged_sig.rjust(n_byte_length, b"\x00")


def _test_rsa_signing(ptext, bits=1024, hash_cls=SHA1):
    print("Generating a public/private key pair, please wait.")
    pubkey, privkey = make_rsa_keys(bits)

    print(f"Signing '{ptext.decode()}'.")
    sig = sign_rsa(ptext, privkey, hash_cls)

    print("Signature validates:", verify_rsa(ptext, sig, pubkey, hash_cls))


def _test_rsa_forging(ptext, bits=1024, hash_cls=SHA1):
    print("Generating a public key, please wait.")
    pubkey = make_rsa_keys(bits)[0]  # Discard the private key.

    print(f"Forging a signature for '{ptext.decode()}'.")
    sig = forge_rsa_e3(ptext, pubkey, hash_cls)

    print("Forgery validates:", verify_rsa(ptext, sig, pubkey, hash_cls))


def main():
    # Intentionally delayed import.
    from hashlib import sha256

    tests = {
        "Testing our RSA signature implementation.": [
            _test_rsa_signing,
            b"Mary had a little lamb",
            b"His fleece was white as snow",
        ],
        "Now, we'll forge signatures that can fool it.": [
            _test_rsa_forging,
            b"hi mom",
            b"And everywhere that Mary went",
        ],
    }

    for description, test in tests.items():
        print(description)
        print()

        func = test[0]

        print("Using 1024-bit modulus, SHA-1 hash.")
        func(test[1], 1024, SHA1)
        print()

        print("Using 1536-bit modulus, SHA-256 hash.")
        func(test[2], 1536, sha256)
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
