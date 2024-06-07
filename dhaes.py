from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def rand():
    return number.getRandomNBitInteger(256)

def PublicKey(g: int, a_or_b: int, p: int):
    risultato = pow(g, a_or_b, p)
    return risultato

def SharedSecret(b: int, a: int, p: int):
    SharedSecret = pow(b, a, p)
    return SharedSecret

def EncryptAES(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    Ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return Ciphertext, nonce

def DecryptAES(key, nonce, Ciphertext: bytes):
    decifratore = AES.new(key, AES.MODE_EAX, nonce=nonce)

    messaggio_decifrato = decifratore.decrypt(Ciphertext)
    return messaggio_decifrato


def key_AES(SharedSecret_: bytes):
    hash_object = SHA256.new(data=SharedSecret_)
    return hash_object.digest()