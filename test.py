#!/usr/bin/env python3

import os
import random
import subprocess
import sys
from os import path
from string import ascii_letters, digits

allchars = ascii_letters + digits + ",.;?!()"
cheater = "cheater: it is forbidden to decrypt the challenge ciphertext"


def verify(s: str, note: str):
    for c in s:
        if c not in allchars:
            raise Exception(note)
    return s


def gen_text(length: int):
    return "".join(random.choice(allchars) for _ in range(length))


def compile(example: str):
    proc = subprocess.run(
        f"cargo build --release --example {example}", shell=True, capture_output=True
    )
    if proc.returncode != 0:
        raise Exception("Code does not compile")
    proc = subprocess.run(f"cp target/release/examples/{example} g2", shell=True)
    if not path.isfile("g2"):
        raise Exception("Executable is missing")
    return
    proc = subprocess.run(["ldd", "g2"], capture_output=True)
    if "not a dynamic executable" not in proc.stderr.decode():
        raise Exception("Executable is not statically linked")


def encrypt(plaintext: str, key: str = ""):
    if not key:
        proc = subprocess.run(
            f"./g2 --encrypt '{plaintext}'", shell=True, capture_output=True
        )
    else:
        proc = subprocess.run(
            f"./g2 --encrypt '{plaintext}' --key <(echo '{key}')",
            shell=True,
            executable="/bin/bash",
            capture_output=True,
        )
    if proc.returncode != 0:
        raise Exception("Encryption failed to run")
    return verify(
        proc.stdout.decode().rstrip("\n"), "Encryption generated invalid output"
    )


def decrypt(ciphertext: str, key: str = ""):
    if not key:
        proc = subprocess.run(
            f"./g2 --decrypt '{ciphertext}'", shell=True, capture_output=True
        )
    else:
        proc = subprocess.run(
            f"./g2 --decrypt '{ciphertext}' --key <(echo '{key}')",
            shell=True,
            executable="/bin/bash",
            capture_output=True,
        )
    if proc.returncode != 0:
        raise Exception("Decryption failed to run")
    result = proc.stdout.decode().rstrip("\n")
    return (
        result
        if result == cheater
        else verify(result, "Decryption generated invalid output")
    )


def generate():
    proc = subprocess.run("./g2 --generate", shell=True, capture_output=True)
    if proc.returncode != 0:
        raise Exception("Key generation failed to run")
    return verify(
        proc.stdout.decode().rstrip("\n"), "Implementation generated invalid key"
    )


def get_challenge_plaintext(example: str):
    try:
        cpt = open(f"examples/{example}/plaintext.txt").read().rstrip("\n")
        if not cpt:
            raise Exception("Challenge plaintext is empty")
        return verify(cpt, "Challenge plaintext is invalid")
    except Exception as e:
        raise Exception(f"Failed to get challenge plaintext: {e}")


def get_challenge_ciphertext(example: str):
    try:
        cct = open(f"examples/{example}/ciphertext.txt").read().rstrip("\n")
        if not cct:
            raise Exception("Challenge ciphertext is empty")
        return verify(cct, "Challenge ciphertext is invalid")
    except Exception as e:
        raise Exception(f"Failed to get challenge ciphertext: {e}")


def get_default_key(example: str):
    try:
        dk = open(f"examples/{example}/key.txt").read().rstrip("\n")
        if not dk:
            raise Exception("Default key is empty")
        return verify(dk, "Default key is invalid")
    except Exception as e:
        raise Exception(f"Failed to get default key: {e}")


def do_tests(example: str):
    print("Removing existing executable if there is one... ", end="")
    try:
        os.remove("g2")
    except:
        pass
    if path.isfile("g2"):
        raise Exception('Existing executable "g2" not removable')
    print("Done!")

    print("Compiling code... ", end="")
    compile(example)
    print("Success!")

    print("Fetching challenge plaintext... ", end="")
    cpt = get_challenge_plaintext(example)
    print("Success!")

    print("Fetching challenge ciphertext... ", end="")
    cct = get_challenge_ciphertext(example)
    print("Success!")

    print("Fetching default key... ", end="")
    dk = get_default_key(example)
    print("Success!")

    print("Checking decryption consistency... ", end="")
    for _ in range(5):
        pt = gen_text(100)
        key = generate()
        ct = encrypt(pt, key)
        for _ in range(10):
            if decrypt(ct, key) != pt:
                raise Exception("Decryption is non-deterministic")
    print("Success!")

    print("Verifying default key... ", end="")
    for _ in range(10):
        pt = gen_text(100)
        ct = encrypt(pt, dk)
        if decrypt(ct) != decrypt(ct, dk) or decrypt(ct) != pt:
            raise Exception("Default key is not genuine")
    for _ in range(10):
        pt = gen_text(100)
        ct = encrypt(pt)
        if decrypt(ct) != decrypt(ct, dk) or decrypt(ct, dk) != pt:
            raise Exception("Default key is not genuine")
    print("Success!")

    print("Checking challenge ciphertext correctness... ", end="")
    for _ in range(10):
        if decrypt(cct, dk) != cpt:
            raise Exception("Challenge ciphertext is incorrect")
    print("Success!")

    print("Testing if challenge ciphertext is protected... ", end="")
    if decrypt(cct) != cheater:
        raise Exception("Challenge ciphertext is unprotected")
    print("Success!")

    print("Testing encryption/decryption with default key... ", end="")
    for i in range(10):
        message = gen_text(random.randint(100 * i, 100 * (i + 1)))
        if decrypt(encrypt(message)) != message:
            raise Exception("Encryption/decryption does not work correctly")
    print("Success!")

    keys = set()
    print("Testing encryption/decryption with generated key... ", end="")
    for i in range(20):
        key = generate()
        keys.add(key)
        message = gen_text(random.randint(10 * i, 10 * (i + 1)))
        if decrypt(encrypt(message, key), key) != message:
            raise Exception("Encryption/decryption does not work correctly")
    if len(keys) == 1:
        raise Exception("Key generation must not always return the same value.")
    print("Success!")

    print("You passed the basic tests.")
    os.remove("g2")


if __name__ == "__main__":
    try:
        do_tests(sys.argv[1])
    except Exception as e:
        print(e)
        print("You did not pass all tests.")
        exit(1)
