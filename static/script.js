document.addEventListener("DOMContentLoaded", () => {
    const cipherSelect = document.getElementById("cipher-select");
    const keyGroups = document.querySelectorAll(".key-group");
    
    // Auto-uppercase Enigma
    const enigmaInputs = [document.getElementById("enigma-1"), document.getElementById("enigma-2"), document.getElementById("enigma-3")];
    enigmaInputs.forEach(input => {
        if(input) input.addEventListener("input", function() { this.value = this.value.toUpperCase().replace(/[^A-Z]/g, ''); });
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
            const r1 = document.getElementById('enigma-1').value || 'A';
            const r2 = document.getElementById('enigma-2').value || 'A';
            const r3 = document.getElementById('enigma-3').value || 'A';
            payload.key_enigma = r1 + r2 + r3;
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
