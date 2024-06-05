from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def rand():
    return number.getRandomNBitInteger(256)

def calcola(g, a_b, p):
    risultato = pow(g, a_b, p)
    return risultato

def calcolaK(chiesto, a, p):
    condiviso = pow(chiesto, a, p)
    return condiviso

def encrypt_mex(key, messaggio):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    if isinstance(messaggio,bytes):
        testo_cifrato = cipher.encrypt(messaggio)
    else:
        testo_cifrato = cipher.encrypt(messaggio.encode('utf-8'))
    return testo_cifrato, nonce

def decrypt_mex(key, nonce, testo_cifrato):
    decifratore = AES.new(key, AES.MODE_EAX, nonce=nonce)

    messaggio_decifrato = decifratore.decrypt(testo_cifrato)
    return messaggio_decifrato


def key_AES(from_key):
    hash_object = SHA256.new(data=from_key)
    return hash_object.digest()