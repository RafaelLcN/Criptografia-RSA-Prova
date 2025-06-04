import random
import math
from sympy import isprime

def generate_prime(bits=1024):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if isprime(num):
            return num

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_rsa_keys(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    while True:
        e = random.randint(2, phi - 1)
        if math.gcd(e, phi) == 1:
            break
    
    d = modinv(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(message, public_key):
    e, n = public_key
    m_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    if m_int >= n:
        raise ValueError("Mensagem muito longa para a chave RSA")
    c = pow(m_int, e, n)
    return c

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    m_int = pow(ciphertext, d, n)
    message = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
    return message