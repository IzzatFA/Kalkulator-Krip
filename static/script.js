document.addEventListener("DOMContentLoaded", () => {
    const cipherSelect = document.getElementById("cipher-select");
    const keyGroups = document.querySelectorAll(".key-group");
    
    // Auto-uppercase Enigma config text inputs
    const enigmaInputs = [document.getElementById("enigma-rings"), document.getElementById("enigma-pos"), document.getElementById("enigma-plugboard")];
    enigmaInputs.forEach(input => {
        if(input) input.addEventListener("input", function() { this.value = this.value.toUpperCase().replace(/[^A-Z ]/g, ''); });
    });

    cipherSelect.addEventListener("change", (e) => {
        keyGroups.forEach(g => g.classList.remove("active"));
        const activeGroup = document.getElementById(`key-${e.target.value}`);
        if(activeGroup) activeGroup.classList.add("active");
        document.getElementById("output-text").value = "";
        document.getElementById("error-msg").textContent = "";
    });
});

async function processText(action) {
    const cipherType = document.getElementById('cipher-select').value;
    const text = document.getElementById('input-text').value.trim();
    const errorMsg = document.getElementById('error-msg');
    const outputText = document.getElementById('output-text');
    
    errorMsg.textContent = "";
    if(!text) { errorMsg.textContent = "Please enter some text."; return; }

    const payload = { action, cipher_type: cipherType, text };

    try {
        if(cipherType === 'vigenere') payload.key_vigenere = document.getElementById('vigenere-key').value;
        else if(cipherType === 'affine') {
            payload.key_affine_a = parseInt(document.getElementById('affine-a').value) || 1;
            payload.key_affine_b = parseInt(document.getElementById('affine-b').value) || 0;
        }
        else if(cipherType === 'playfair') payload.key_playfair = document.getElementById('playfair-key').value;
        else if(cipherType === 'hill') payload.key_hill = document.getElementById('hill-key').value;
        else if(cipherType === 'enigma') {
            payload.enigma_reflector = document.getElementById('enigma-reflector').value;
            payload.enigma_r1 = document.getElementById('enigma-r1').value;
            payload.enigma_r2 = document.getElementById('enigma-r2').value;
            payload.enigma_r3 = document.getElementById('enigma-r3').value;
            
            const rings = document.getElementById('enigma-rings').value || 'AAA';
            const pos = document.getElementById('enigma-pos').value || 'AAA';
            
            payload.enigma_rings = rings.padEnd(3, 'A').substring(0,3);
            payload.enigma_pos = pos.padEnd(3, 'A').substring(0,3);
            payload.enigma_plugboard = document.getElementById('enigma-plugboard').value;
        }

        const res = await fetch('/api/process', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if(data.error) {
            errorMsg.textContent = data.error;
            outputText.value = "";
        } else {
            outputText.value = data.result;
        }
    } catch (err) {
        errorMsg.textContent = "Error communicating with server.";
        console.error(err);
    }
}
