// rsa.js
// Демонстраційна реалізація RSA з BigInt.
// Поля p, q, e вводяться вручну; n та phi обчислюються автоматично.
// d можна ввести вручну або обчислити кнопкою.

(function(){
  // DOM
  const pIn = document.getElementById('p');
  const qIn = document.getElementById('q');
  const nIn = document.getElementById('n');
  const phiIn = document.getElementById('phi');
  const eIn = document.getElementById('e');
  const dIn = document.getElementById('d');

  const computeNPhiBtn = document.getElementById('computeNPhi');
  const computeDBtn = document.getElementById('computeD');

  const plaintextEl = document.getElementById('plaintext');
  const encryptBtn = document.getElementById('encryptBtn');

  const ciphertextEl = document.getElementById('ciphertext');
  const decryptBtn = document.getElementById('decryptBtn');
  const decryptedEl = document.getElementById('decrypted');
  const clearBtn = document.getElementById('clearBtn');

  // допоміжні функції з BigInt
  function toBigIntSafe(s){
    try{
      if(typeof s === 'bigint') return s;
      if(s === null || s === undefined || s === '') throw 'empty';
      // дозволяємо вводити десяткові або з пробілами
      const cleaned = String(s).replace(/\s+/g,'');
      return BigInt(cleaned);
    }catch(e){
      throw new Error('Неправильний ввід числа: '+s);
    }
  }

  function egcd(a, b){
    a = BigInt(a); b = BigInt(b);
    let x0 = 1n, y0 = 0n;
    let x1 = 0n, y1 = 1n;
    while(b !== 0n){
      const q = a / b;
      const r = a % b;
      const x2 = x0 - q * x1;
      const y2 = y0 - q * y1;
      a = b; b = r;
      x0 = x1; y0 = y1;
      x1 = x2; y1 = y2;
    }
    return {g: a, x: x0, y: y0};
  }

  function modInverse(e, phi){
    const res = egcd(e, phi);
    if(res.g !== 1n) return null;
    let inv = res.x % phi;
    if(inv < 0n) inv += phi;
    return inv;
  }

  function modPow(base, exp, mod){
    base = base % mod;
    if(base < 0n) base += mod;
    let result = 1n;
    while(exp > 0n){
      if(exp & 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return result;
  }

  // Обчислити n і phi з p та q
  function computeNandPhi(){
    try{
      const p = toBigIntSafe(pIn.value);
      const q = toBigIntSafe(qIn.value);
      if(p <= 1n || q <= 1n) throw 'p і q мають бути >1';
      const n = p * q;
      const phi = (p - 1n) * (q - 1n);
      nIn.value = n.toString();
      phiIn.value = phi.toString();
      return {p, q, n, phi};
    }catch(err){
      alert('Помилка при обчисленні n/φ: ' + err);
      throw err;
    }
  }

  // Кнопка: обчислити n і phi
  computeNPhiBtn.addEventListener('click', ()=>{
    try{
      computeNandPhi();
    }catch(e){}
  });

  // Кнопка: обчислити d
  computeDBtn.addEventListener('click', ()=>{
    try{
      const {phi} = computeNandPhi();
      const e = toBigIntSafe(eIn.value);
      const d = modInverse(e, phi);
      if(d === null){
        alert('Оберненого елементу не існує (НСД(e, φ) ≠ 1)');
        return;
      }
      dIn.value = d.toString();
      alert('d обчислено і вписано у відповідне поле');
    }catch(err){}
  });

  // Шифрування (кожен символ окремо)
  encryptBtn.addEventListener('click', ()=>{
    try{
      const {n} = computeNandPhi();
      const e = toBigIntSafe(eIn.value);
      const text = String(plaintextEl.value || '');
      if(text.length === 0){
        alert('Порожній текст для шифрування');
        return;
      }
      const blocks = [];
      for(const ch of text){
        const code = BigInt(ch.codePointAt(0));
        if(code >= n){
          alert(`Код символу ${code} >= n (${n}). Збільши p або q або використовуй блочне кодування.`);
          return;
        }
        const c = modPow(code, e, n);
        blocks.push(c.toString());
      }
      ciphertextEl.value = blocks.join(',');
      decryptedEl.value = '';
      alert('Текст зашифровано. Перевір поле "Шифротекст".');
    }catch(err){
      alert('Помилка при шифруванні: ' + err);
    }
  });

  // Дешифрування (з поля ciphertext)
  decryptBtn.addEventListener('click', ()=>{
    try{
      const {n} = computeNandPhi();
      if(!dIn.value){
        alert('Спочатку введи d або обчисли його.');
        return;
      }
      const d = toBigIntSafe(dIn.value);
      const cipher = String(ciphertextEl.value || '').trim();
      if(!cipher){
        alert('Поле шифротексту порожнє.');
        return;
      }
      const parts = cipher.split(',').map(s => s.trim()).filter(Boolean);
      const chars = [];
      for(const pText of parts){
        const c = toBigIntSafe(pText);
        const m = modPow(c, d, n);
        // Перетворюємо назад у символ
        const num = Number(m); // безпечне для маленьких тестів
        chars.push(String.fromCodePoint(num));
      }
      decryptedEl.value = chars.join('');
      alert('Розшифровано успішно.');
    }catch(err){
      alert('Помилка при дешифруванні: ' + err);
    }
  });

  clearBtn.addEventListener('click', ()=>{
    plaintextEl.value=''; ciphertextEl.value=''; decryptedEl.value=''; dIn.value='';
  });

  // Ініціалізація: можна залишити порожні значення або приклади
  pIn.value = pIn.value || '';
  qIn.value = qIn.value || '';
  eIn.value = eIn.value || '';
})();
