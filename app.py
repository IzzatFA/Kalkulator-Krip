from flask import Flask, request, jsonify, render_template
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
            if action == 'encrypt': result = ciphers.vigenere_encrypt(text, key)
            else: result = ciphers.vigenere_decrypt(text, key)
                
        elif cipher_type == 'affine':
            a = data.get('key_affine_a', 1)
            b = data.get('key_affine_b', 0)
            if action == 'encrypt': result = ciphers.affine_encrypt(text, a, b)
            else: result = ciphers.affine_decrypt(text, a, b)
                
        elif cipher_type == 'playfair':
            key = data.get('key_playfair', 'KEYWORD')
            if action == 'encrypt': result = ciphers.playfair_encrypt(text, key)
            else: result = ciphers.playfair_decrypt(text, key)
                
        elif cipher_type == 'hill':
            key = data.get('key_hill', '5 8 17 3') # Default 2x2 matrix
            if action == 'encrypt': result = ciphers.hill_encrypt(text, key)
            else: result = ciphers.hill_decrypt(text, key)
                
        elif cipher_type == 'enigma':
            rotors = (data.get('enigma_r1', 'I'), data.get('enigma_r2', 'II'), data.get('enigma_r3', 'III'))
            reflector = data.get('enigma_reflector', 'UKW-B')
            rings = data.get('enigma_rings', 'AAA')
            pos = data.get('enigma_pos', 'AAA')
            plugboard = data.get('enigma_plugboard', '')
            
            result = ciphers.full_enigma_encrypt_decrypt(text, rotors, reflector, rings, pos, plugboard)
            
        else:
            error = "Invalid cipher type."
            
        if result and result.startswith('Error:'):
            error = result
            result = ""
            
    except Exception as e:
        error = str(e)
        
    return jsonify({'result': result, 'error': error})

if __name__ == '__main__':
    app.run(debug=True, port=5000, host="0.0.0.0")
