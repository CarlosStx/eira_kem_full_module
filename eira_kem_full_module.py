
import os
from Crypto.Hash import SHA3_512, HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad

# ==========================
# EIRA-KEM KEY ENCAPSULATION
# ==========================

def generate_keypair():
    sk = os.urandom(64)
    h = SHA3_512.new(sk).digest()
    pk = h[:32]
    return pk, sk

def encapsulate(pk, sk):
    r = os.urandom(32)
    material = SHA3_512.new(sk + r + pk).digest()
    K = HKDF(master=material, key_len=32, salt=None, hashmod=SHA256)
    nonce = os.urandom(12)
    cipher = AES.new(K, AES.MODE_GCM, nonce=nonce)
    plaintext = b"EIRA-ENCAPSULATED"
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    capsule = {
        "r": r,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag
    }
    return capsule, K

def decapsulate(sk, capsule):
    h = SHA3_512.new(sk).digest()
    pk = h[:32]
    material = SHA3_512.new(sk + capsule["r"] + pk).digest()
    K = HKDF(master=material, key_len=32, salt=None, hashmod=SHA256)
    cipher = AES.new(K, AES.MODE_GCM, nonce=capsule["nonce"])
    plaintext = cipher.decrypt_and_verify(capsule["ciphertext"], capsule["tag"])
    if plaintext != b"EIRA-ENCAPSULATED":
        raise ValueError("Etiqueta no válida")
    return K

# ==========================
# TEST CCA2 SIMULATION
# ==========================

def test_ind_cca2_simulation():
    pk, sk = generate_keypair()
    encapsulated, shared_key_1 = encapsulate(pk, sk)
    shared_key_2 = decapsulate(sk, encapsulated)

    print("Clave compartida OK:", shared_key_1 == shared_key_2)
    print("Key HEX:", shared_key_1.hex())

if __name__ == "__main__":
    test_ind_cca2_simulation()
