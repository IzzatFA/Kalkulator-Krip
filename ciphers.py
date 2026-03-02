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

# --- Full Enigma Cipher (M3) ---
class EnigmaMachine:
    # Full wiring for standard M3 Enigma rotors and reflectors
    WIRINGS = {
        'I':    'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
        'II':   'AJDKSIRUXBLHWTMCQGZNPYFVOE',
        'III':  'BDFHJLCPRTXVZNYEIWGAKMUSQO',
        'IV':   'ESOVPZJAYQUIRHXLNFTGKDCMWB',
        'V':    'VZBRGITYUPSDNHLXAWMJQOFECK',
        'UKW-B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
        'UKW-C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL'
    }
    
    # Notch positions (when these step down, the next rotor turns)
    NOTCHES = {
        'I': 'Q', 'II': 'E', 'III': 'V', 'IV': 'J', 'V': 'Z'
    }

    def __init__(self, rotors=('I', 'II', 'III'), reflector='UKW-B', ring_settings='AAA', start_pos='AAA', plugboard=""):
        self.r_types = rotors
        self.rotors = [self.WIRINGS[r] for r in rotors]
        self.reflector = self.WIRINGS[reflector]
        self.rings = [ALPHABET.index(c.upper()) for c in ring_settings]
        self.pos = [ALPHABET.index(c.upper()) for c in start_pos]
        
        # Setup plugboard
        self.plugboard = {}
        if plugboard:
            pairs = plugboard.upper().split()
            for pair in pairs:
                if len(pair) == 2:
                    self.plugboard[pair[0]] = pair[1]
                    self.plugboard[pair[1]] = pair[0]

    def _step_rotors(self):
        # M3 Enigma has a double stepping anomaly on the middle rotor
        right_notch = ALPHABET.index(self.NOTCHES[self.r_types[2]])
        middle_notch = ALPHABET.index(self.NOTCHES[self.r_types[1]])
        
        step_middle = self.pos[2] == right_notch
        step_left = self.pos[1] == middle_notch
        
        # Right rotor always steps
        self.pos[2] = (self.pos[2] + 1) % 26
        
        if step_middle or step_left:
            self.pos[1] = (self.pos[1] + 1) % 26
            if step_left:
                self.pos[0] = (self.pos[0] + 1) % 26

    def _pass_through_plugboard(self, char):
        return self.plugboard.get(char, char)

    def _pass_rotor(self, char_idx, r_idx, reverse=False):
        p = self.pos[r_idx]
        ring = self.rings[r_idx]
        
        shift = (p - ring) % 26
        
        if not reverse:
            # Entry idx taking ring setting and pos into account
            entry_idx = (char_idx + shift) % 26
            out_char = self.rotors[r_idx][entry_idx]
            out_idx = ALPHABET.index(out_char)
            return (out_idx - shift) % 26
        else:
            # Backward pass
            char_to_find = ALPHABET[(char_idx + shift) % 26]
            idx_in_rotor = self.rotors[r_idx].index(char_to_find)
            return (idx_in_rotor - shift) % 26

    def process(self, char):
        char = self._pass_through_plugboard(char)
        char_idx = ALPHABET.index(char)
        
        self._step_rotors()
        
        # Forward through rotors 3 -> 2 -> 1
        for i in [2, 1, 0]:
            char_idx = self._pass_rotor(char_idx, i, reverse=False)
            
        # Reflector
        char_idx = ALPHABET.index(self.reflector[char_idx])
        
        # Backward through rotors 1 -> 2 -> 3
        for i in [0, 1, 2]:
            char_idx = self._pass_rotor(char_idx, i, reverse=True)
            
        out_char = ALPHABET[char_idx]
        return self._pass_through_plugboard(out_char)

def full_enigma_encrypt_decrypt(text, rotors, reflector, rings, pos, plugboard):
    text = format_text(text)
    machine = EnigmaMachine(rotors, reflector, rings, pos, plugboard)
    return ''.join([machine.process(c) for c in text])
