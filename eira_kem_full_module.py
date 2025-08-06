
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
    sk = os.urandom(64)  # Secreto privado
    h = SHA3_512.new(sk).digest()
    pk = h[:32]          # Parte pública
    return pk, sk

def encapsulate(pk, sk):
    r = os.urandom(32)  # Entropía temporal
    # Derivar salt de r, sk y pk
    salt = SHA3_512.new(sk + r + pk).digest()

    # Derivar clave simétrica K usando HKDF con salt
    K = HKDF(master=r + pk, key_len=32, salt=salt, hashmod=SHA256)

    nonce = get_random_bytes(12)
    cipher = AES.new(K, AES.MODE_GCM, nonce=nonce)
    plaintext = b"EIRA-ENCAPSULATED"
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    encapsulated_data = {
        "r": r,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag
    }

    return encapsulated_data, K

def decapsulate(sk, encapsulated_data):
    pk = SHA3_512.new(sk).digest()[:32]
    r = encapsulated_data["r"]
    salt = SHA3_512.new(sk + r + pk).digest()

    # Regenerar K con los mismos parámetros
    K = HKDF(master=r + pk, key_len=32, salt=salt, hashmod=SHA256)
    cipher = AES.new(K, AES.MODE_GCM, nonce=encapsulated_data["nonce"])
    plaintext = cipher.decrypt_and_verify(
        encapsulated_data["ciphertext"],
        encapsulated_data["tag"]
    )
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
