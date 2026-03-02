import os

os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

app_py = """from flask import Flask, request, jsonify, render_template
import ciphers

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/process', methods=['POST'])
def process():
    data = request.json
    text = data.get('text', '')
    cipher_type = data.get('cipher_type', '')
    action = data.get('action', 'encrypt')
    
    result = ""
    error = ""
    
    try:
        if cipher_type == 'vigenere':
            key = data.get('key_vigenere', 'KEY')
            if action == 'encrypt':
                result = ciphers.vigenere_encrypt(text, key)
            else:
                result = ciphers.vigenere_decrypt(text, key)
                
        elif cipher_type == 'affine':
            a = data.get('key_affine_a', 1)
            b = data.get('key_affine_b', 0)
            if action == 'encrypt':
                result = ciphers.affine_encrypt(text, a, b)
            else:
                result = ciphers.affine_decrypt(text, a, b)
                
        elif cipher_type == 'playfair':
            key = data.get('key_playfair', 'KEYWORD')
            if action == 'encrypt':
                result = ciphers.playfair_encrypt(text, key)
            else:
                result = ciphers.playfair_decrypt(text, key)
                
        elif cipher_type == 'hill':
            key = data.get('key_hill', '5 8 17 3') # Default 2x2 matrix
            if action == 'encrypt':
                result = ciphers.hill_encrypt(text, key)
            else:
                result = ciphers.hill_decrypt(text, key)
                
        elif cipher_type == 'enigma':
            positions = data.get('key_enigma', 'AAA')
            result = ciphers.enigma_encrypt_decrypt(text, positions)
            
        else:
            error = 'Invalid cipher type.'
            
        if result and result.startswith('Error:'):
            error = result
            result = ""
            
    except Exception as e:
        error = str(e)
        
    return jsonify({
        'result': result,
        'error': error
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
"""

ciphers_py = """import numpy as np
import string

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

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
        return 'Error: Keys must be integers.'
    if ext_gcd(a, 26)[0] != 1: return 'Error: Key a must be coprime to 26.'
    return ''.join([ALPHABET[(a * ALPHABET.index(c) + b) % 26] for c in text])

def affine_decrypt(text, a, b):
    text = format_text(text)
    try:
        a, b = int(a), int(b)
    except ValueError:
        return 'Error: Keys must be integers.'
    a_inv = mod_inverse(a, 26)
    if a_inv is None: return 'Error: Key A has no modular inverse.'
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
    if len(text) % 2 != 0: return 'Error: Ciphertext length must be even.'
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
    except: return 'Error: Invalid matrix format.'
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
    except: return 'Error: Invalid matrix format.'
    det = int(np.round(np.linalg.det(key_matrix)))
    if ext_gcd(det % 26, 26)[0] != 1: return 'Error: Matrix not invertible.'
    adj = np.round(np.linalg.det(key_matrix) * np.linalg.inv(key_matrix)).astype(int)
    inv_matrix = (mod_inverse(det % 26, 26) * adj) % 26
    if len(text) % size != 0: return 'Error: Ciphertext length invalid.'
    result = []
    for i in range(0, len(text), size):
        block = [ALPHABET.index(c) for c in text[i:i+size]]
        decrypted = np.dot(inv_matrix, np.array(block).reshape(size, 1)) % 26
        result.extend([ALPHABET[v[0]] for v in decrypted])
    return ''.join(result)

# --- Enigma Cipher ---
class EnigmaMachine:
    def __init__(self, r1, r2, r3):
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
"""

req_txt = "Flask==3.0.3\nnumpy==1.26.4\n"

index_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CryptoGlass</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <div class="bg-shape shape-1"></div>
    <div class="bg-shape shape-2"></div>
    <main class="container">
        <h1>Crypto<span class="highlight">Glass</span></h1>
        <section class="glass-panel">
            <select id="cipher-select" class="glass-input">
                <option value="vigenere">Vigenere Cipher</option>
                <option value="affine">Affine Cipher</option>
                <option value="playfair">Playfair Cipher</option>
                <option value="hill">Hill Cipher</option>
                <option value="enigma">Enigma Cipher (M3)</option>
            </select>
            <div id="keys" class="keys-container">
                <div id="key-vigenere" class="active"><input id="vigenere-key" class="glass-input" value="CRYSTAL"></div>
                <div id="key-affine" style="display:none;"><input id="affine-a" class="glass-input" value="5"><input id="affine-b" class="glass-input" value="8"></div>
                <div id="key-playfair" style="display:none;"><input id="playfair-key" class="glass-input" value="MONARCHY"></div>
                <div id="key-hill" style="display:none;"><input id="hill-key" class="glass-input" value="5 8 17 3"></div>
                <div id="key-enigma" style="display:none;"><input id="enigma-1" class="glass-input" value="A" maxlength="1"><input id="enigma-2" class="glass-input" value="A" maxlength="1"><input id="enigma-3" class="glass-input" value="A" maxlength="1"></div>
            </div>
            <textarea id="input-text" class="glass-input" rows="3" placeholder="Input text..."></textarea>
            <div class="actions">
                <button onclick="process('encrypt')" class="btn btn-primary">Encrypt</button>
                <button onclick="process('decrypt')" class="btn btn-secondary">Decrypt</button>
            </div>
            <textarea id="output-text" class="glass-input" rows="3" readonly></textarea>
            <div id="error-msg" class="error"></div>
        </section>
    </main>
    <script src="{{ url_for('static', filename='script.js') }}"></script>
</body>
</html>
"""

style_css = """:root {
    --bg: #0b0f19; --primary: #6366f1; --secondary: #ec4899;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
body { background: var(--bg); color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; overflow: hidden; }
.bg-shape { position: absolute; border-radius: 50%; filter: blur(80px); z-index: -1; }
.shape-1 { width: 400px; height: 400px; background: var(--primary); top: -100px; left: -100px; opacity: 0.5; }
.shape-2 { width: 500px; height: 500px; background: var(--secondary); bottom: -150px; right: -100px; opacity: 0.5; }
.container { width: 100%; max-width: 600px; padding: 2rem; z-index: 1; text-align: center; }
h1 { font-size: 3rem; margin-bottom: 2rem; }
.highlight { background: linear-gradient(135deg, var(--primary), var(--secondary)); -webkit-background-clip: text; color: transparent; }
.glass-panel { background: rgba(255,255,255,0.05); backdrop-filter: blur(16px); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 2rem; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
.glass-input { background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 1rem; color: #fff; width: 100%; margin-bottom: 1rem; outline: none; transition: 0.3s; }
.glass-input:focus { border-color: var(--primary); }
.keys-container div { display: flex; gap: 1rem; }
.btn { flex: 1; padding: 1rem; border: none; border-radius: 12px; cursor: pointer; color: white; transition: 0.3s; font-weight: 600; width: 48%; }
.actions { display: flex; justify-content: space-between; margin-bottom: 1rem; }
.btn-primary { background: linear-gradient(135deg, var(--primary), #818cf8); }
.btn-secondary { background: linear-gradient(135deg, var(--secondary), #f472b6); }
.error { color: #ef4444; }
"""

script_js = """document.getElementById('cipher-select').addEventListener('change', e => {
    document.querySelectorAll('.keys-container > div').forEach(d => d.style.display = 'none');
    document.getElementById(`key-${e.target.value}`).style.display = 'flex';
});

async function process(action) {
    const p = { action, cipher_type: document.getElementById('cipher-select').value, text: document.getElementById('input-text').value };
    if(p.cipher_type === 'vigenere') p.key_vigenere = document.getElementById('vigenere-key').value;
    else if(p.cipher_type === 'affine') { p.key_affine_a = document.getElementById('affine-a').value; p.key_affine_b = document.getElementById('affine-b').value; }
    else if(p.cipher_type === 'playfair') p.key_playfair = document.getElementById('playfair-key').value;
    else if(p.cipher_type === 'hill') p.key_hill = document.getElementById('hill-key').value;
    else if(p.cipher_type === 'enigma') p.key_enigma = document.getElementById('enigma-1').value + document.getElementById('enigma-2').value + document.getElementById('enigma-3').value;
    
    const res = await fetch('/api/process', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(p) });
    const data = await res.json();
    document.getElementById('error-msg').innerText = data.error || '';
    if(!data.error) document.getElementById('output-text').value = data.result;
}
"""

with open('app.py', 'w') as f: f.write(app_py)
with open('ciphers.py', 'w') as f: f.write(ciphers_py)
with open('requirements.txt', 'w') as f: f.write(req_txt)
with open('templates/index.html', 'w') as f: f.write(index_html)
with open('static/style.css', 'w') as f: f.write(style_css)
with open('static/script.js', 'w') as f: f.write(script_js)
print("Files generated!")
