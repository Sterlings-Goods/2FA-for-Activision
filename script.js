/***************************************************
 * Sterling Goods - Tactical Authenticator Script
 ***************************************************/
const secretInput       = document.getElementById("secret");
const digitsInput       = document.getElementById("digits");
const periodInput       = document.getElementById("period");
const algorithmSelect   = document.getElementById("algorithm");

const countdownElem     = document.getElementById("countdown");
const currentTOTPElem   = document.getElementById("currentTOTP");
const copyBtn           = document.getElementById("copyBtn");

let totpIntervalId      = null;

// Utility: Base32 Decode
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const sanitized = input.replace(/=+$/, "").toUpperCase().replace(/[^A-Z2-7]+/g, "");
  
  let bits = "";
  const output = [];
  
  for (let i = 0; i < sanitized.length; i++) {
    const val = alphabet.indexOf(sanitized[i]);
    if (val === -1) throw new Error("Invalid Base32 character");
    bits += val.toString(2).padStart(5, "0");
  }
  
  for (let j = 0; j + 7 < bits.length; j += 8) {
    output.push(parseInt(bits.substr(j, 8), 2));
  }
  
  return new Uint8Array(output);
}

// Utility: HMAC Generation
async function hmacSign(keyBytes, msgBytes, algorithm) {
  const algoKey = { name: "HMAC", hash: { name: algorithm } };
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, algoKey, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, msgBytes);
  return new Uint8Array(signature);
}

// TOTP Math Logic
async function generateTOTP(secret, timeNow, digits, period, algorithm) {
  const keyBytes = base32Decode(secret);
  const timeStep = Math.floor(timeNow / period);
  
  const msgBytes = new ArrayBuffer(8);
  const msgView  = new DataView(msgBytes);
  msgView.setUint32(0, 0); 
  msgView.setUint32(4, timeStep); 

  const hmac   = await hmacSign(keyBytes, msgBytes, algorithm);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
      ((hmac[offset]     & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) <<  8) |
      ((hmac[offset + 3] & 0xff));

  const fullCode = binCode % (10 ** digits);
  return String(fullCode).padStart(digits, "0");
}

// Display Updates
async function updateTOTPDisplay() {
  const secret    = secretInput.value.trim();
  const digits    = parseInt(digitsInput.value, 10);
  const period    = parseInt(periodInput.value, 10);
  const algorithm = algorithmSelect.value;

  if (!secret) {
    currentTOTPElem.textContent = "------";
    countdownElem.textContent   = "--";
    return;
  }

  const unixTime    = Math.floor(Date.now() / 1000);
  const currentStep = Math.floor(unixTime / period);
  const nextStep    = (currentStep + 1) * period;

  try {
    const currentCode = await generateTOTP(secret, unixTime, digits, period, algorithm);
    currentTOTPElem.textContent = currentCode;

    const secondsLeft = nextStep - unixTime;
    countdownElem.textContent = secondsLeft.toString().padStart(2, '0');
  } catch (err) {
    console.error("Error generating TOTP:", err);
    currentTOTPElem.textContent = "ERROR";
    countdownElem.textContent   = "--";
  }
}

// Listen for User Typing
secretInput.addEventListener("input", updateTOTPDisplay);

// Copy Button Logic
copyBtn.addEventListener("click", async () => {
  const totpValue = currentTOTPElem.textContent.trim();
  if (totpValue && totpValue !== "------" && totpValue !== "ERROR") {
    try {
      await navigator.clipboard.writeText(totpValue);
      copyBtn.classList.add("copied");
      setTimeout(() => copyBtn.classList.remove("copied"), 1500);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  }
});

// Start the Timer Loop
totpIntervalId = setInterval(updateTOTPDisplay, 1000);
updateTOTPDisplay();
// -------------------------------------------------
// AUTO-LOAD & URL SHARING FEATURE (UPDATED)
// -------------------------------------------------

window.addEventListener("DOMContentLoaded", () => {
  const secretField = document.getElementById("secret");
  
  if (!secretField) return;

  // 1. Check the URL for a secret key when the page opens
  const hash = window.location.hash.substring(1).trim();
  if (hash) {
    secretField.value = hash;
    // Simulate a user typing so the original script detects the change
    secretField.dispatchEvent(new Event("input", { bubbles: true }));
  }

  // 2. Automatically update the address bar when you type/paste a key
  secretField.addEventListener("input", (e) => {
    const currentSecret = e.target.value.trim();
    if (currentSecret) {
      window.history.replaceState(null, null, "#" + currentSecret);
    } else {
      window.history.replaceState(null, null, window.location.pathname);
    }
  });
});