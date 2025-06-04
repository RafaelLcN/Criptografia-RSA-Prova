def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sum32(*args):
    return sum(args) & 0xFFFFFFFF

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3)

def sigma1(x):
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10)

def capsigma0(x):
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)

def capsigma1(x):
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)

# Constantes SHA-256
k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Valores de hash iniciais
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def pad_message(message):
    m_bin = ''.join(f'{ord(c):08b}' for c in message)
    m_bin += '1'
    while len(m_bin) % 512 != 448:
        m_bin += '0'
    m_bin += f'{len(message) * 8:064b}'
    return [m_bin[i:i+512] for i in range(0, len(m_bin), 512)]

def parse_block(block):
    w = [int(block[i:i+32], 2) for i in range(0, 512, 32)]
    for i in range(16, 64):
        s0 = sigma0(w[i-15])
        s1 = sigma1(w[i-2])
        w.append(sum32(w[i-16], s0, w[i-7], s1))
    return w

def compress_block(w, H):
    a, b, c, d, e, f, g, h = H
    for i in range(64):
        T1 = sum32(h, capsigma1(e), ch(e, f, g), k[i], w[i])
        T2 = sum32(capsigma0(a), maj(a, b, c))
        h, g, f, e = g, f, e, sum32(d, T1)
        d, c, b, a = c, b, a, sum32(T1, T2)
    return [sum32(x, y) for x, y in zip(H, [a, b, c, d, e, f, g, h])]

def sha256(message, output_type='hex'):
    blocks = pad_message(message)
    H = H0[:]
    for block in blocks:
        w = parse_block(block)
        H = compress_block(w, H)
    if output_type == 'bin':
        return ''.join(f'{h:032b}' for h in H)
    else:
        return ''.join(f'{h:08x}' for h in H)