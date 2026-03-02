import numpy as np
import string

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def format_text(text):
    return ''.join(filter(str.isalpha, text.upper()))

# --- Vigenere Cipher ---
def vigenere_encrypt(text, key):
    text = format_text(text)
    key = format_text(key)
    if not key: return text
    result = []
    for i, char in enumerate(text):
        p = ALPHABET.index(char)
        k = ALPHABET.index(key[i % len(key)])
        result.append(ALPHABET[(p + k) % 26])
    return ''.join(result)

def vigenere_decrypt(text, key):
    text = format_text(text)
    key = format_text(key)
    if not key: return text
    result = []
    for i, char in enumerate(text):
        c = ALPHABET.index(char)
        k = ALPHABET.index(key[i % len(key)])
        result.append(ALPHABET[(c - k) % 26])
    return ''.join(result)

# --- Affine Cipher ---
def ext_gcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return b, x, y

def mod_inverse(a, m):
    g, x, y = ext_gcd(a, m)
    if g != 1: return None
    return x % m

def affine_encrypt(text, a, b):
    text = format_text(text)
    try:
        a, b = int(a), int(b)
    except ValueError:
        return "Error: Keys must be integers."
    if ext_gcd(a, 26)[0] != 1: return "Error: Key a must be coprime to 26."
    return ''.join([ALPHABET[(a * ALPHABET.index(c) + b) % 26] for c in text])

def affine_decrypt(text, a, b):
    text = format_text(text)
    try:
        a, b = int(a), int(b)
    except ValueError:
        return "Error: Keys must be integers."
    a_inv = mod_inverse(a, 26)
    if a_inv is None: return "Error: Key A has no modular inverse."
    return ''.join([ALPHABET[(a_inv * (ALPHABET.index(c) - b)) % 26] for c in text])

# --- Playfair Cipher ---
def generate_playfair_matrix(key):
    key = format_text(key).replace('J', 'I')
    matrix = []
    used = set()
    for char in key + ALPHABET.replace('J', ''):
        if char not in used:
            matrix.append(char)
            used.add(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_pos(matrix, char):
    if char == 'J': char = 'I'
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char: return r, c
    return None, None

def playfair_encrypt(text, key):
    text = format_text(text).replace('J', 'I')
    matrix = generate_playfair_matrix(key)
    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text) and text[i+1] != a:
            b, i = text[i+1], i+2
        else:
            b, i = ('X' if a != 'X' else 'Q'), i+1
        digraphs.append((a, b))
    result = []
    for a, b in digraphs:
        r1, c1 = find_pos(matrix, a)
        r2, c2 = find_pos(matrix, b)
        if r1 == r2: result.extend([matrix[r1][(c1+1)%5], matrix[r2][(c2+1)%5]])
        elif c1 == c2: result.extend([matrix[(r1+1)%5][c1], matrix[(r2+1)%5][c2]])
        else: result.extend([matrix[r1][c2], matrix[r2][c1]])
    return ''.join(result)

def playfair_decrypt(text, key):
    text = format_text(text)
    matrix = generate_playfair_matrix(key)
    if len(text) % 2 != 0: return "Error: Ciphertext length must be even."
    digraphs = [(text[i], text[i+1]) for i in range(0, len(text), 2)]
    result = []
    for a, b in digraphs:
        r1, c1 = find_pos(matrix, a)
        r2, c2 = find_pos(matrix, b)
        if r1 == r2: result.extend([matrix[r1][(c1-1)%5], matrix[r2][(c2-1)%5]])
        elif c1 == c2: result.extend([matrix[(r1-1)%5][c1], matrix[(r2-1)%5][c2]])
        else: result.extend([matrix[r1][c2], matrix[r2][c1]])
    return ''.join(result)

# --- Hill Cipher ---
def hill_encrypt(text, matrix_str):
    text = format_text(text)
    try:
        elements = [int(x) for x in matrix_str.split()]
        size = int(np.sqrt(len(elements)))
        key_matrix = np.array(elements).reshape((size, size))
    except (ValueError, Exception):
        return "Error: Invalid matrix format."
    while len(text) % size != 0: text += 'X'
    result = []
    for i in range(0, len(text), size):
        block = [ALPHABET.index(c) for c in text[i:i+size]]
        encrypted = np.dot(key_matrix, np.array(block).reshape(size, 1)) % 26
        result.extend([ALPHABET[v[0]] for v in encrypted])
    return ''.join(result)

def hill_decrypt(text, matrix_str):
    text = format_text(text)
    try:
        elements = [int(x) for x in matrix_str.split()]
        size = int(np.sqrt(len(elements)))
        key_matrix = np.array(elements).reshape((size, size))
    except (ValueError, Exception):
        return "Error: Invalid matrix format."
    det = int(np.round(np.linalg.det(key_matrix)))
    if ext_gcd(det % 26, 26)[0] != 1: return "Error: Matrix not invertible."
    adj = np.round(np.linalg.det(key_matrix) * np.linalg.inv(key_matrix)).astype(int)
    inv_matrix = (mod_inverse(det % 26, 26) * adj) % 26
    if len(text) % size != 0: return "Error: Ciphertext length invalid."
    result = []
    for i in range(0, len(text), size):
        block = [ALPHABET.index(c) for c in text[i:i+size]]
        decrypted = np.dot(inv_matrix, np.array(block).reshape(size, 1)) % 26
        result.extend([ALPHABET[v[0]] for v in decrypted])
    return ''.join(result)

# --- Enigma Cipher ---
class EnigmaMachine:
    def __init__(self, r1='A', r2='A', r3='A'):
        self.rotors = ['EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'AJDKSIRUXBLHWTMCQGZNPYFVOE', 'BDFHJLCPRTXVZNYEIWGAKMUSQO']
        self.reflector = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'
        self.pos = [ALPHABET.index(r1.upper()), ALPHABET.index(r2.upper()), ALPHABET.index(r3.upper())]

    def step(self):
        self.pos[2] = (self.pos[2] + 1) % 26
        if self.pos[2] == 0:
            self.pos[1] = (self.pos[1] + 1) % 26
            if self.pos[1] == 0: self.pos[0] = (self.pos[0] + 1) % 26

    def pass_rotor(self, char_idx, r_idx, reverse=False):
        p = self.pos[r_idx]
        if not reverse: return (ALPHABET.index(self.rotors[r_idx][(char_idx + p) % 26]) - p) % 26
        return (self.rotors[r_idx].index(ALPHABET[(char_idx + p) % 26]) - p) % 26

    def process(self, char):
        self.step()
        idx = ALPHABET.index(char)
        for i in [2, 1, 0]: idx = self.pass_rotor(idx, i, False)
        idx = ALPHABET.index(self.reflector[idx])
        for i in [0, 1, 2]: idx = self.pass_rotor(idx, i, True)
        return ALPHABET[idx]

def enigma_encrypt_decrypt(text, settings='AAA'):
    if not settings or len(settings) != 3: settings = 'AAA'
    machine = EnigmaMachine(settings[0], settings[1], settings[2])
    return ''.join([machine.process(c) for c in format_text(text)])
