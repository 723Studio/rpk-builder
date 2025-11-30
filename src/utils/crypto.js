'use strict';

const crypto = require('crypto');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

function deriveKey(passphrase, salt) {
  // 64 байта: первые 32 — ключ шифрования AES, вторые 32 — ключ HMAC
  return crypto.scryptSync(passphrase, salt, 64, SCRYPT_PARAMS);
}

function randBytes(n) {
  return crypto.randomBytes(n);
}

// AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
function encryptCbcHmac(encKey32, hmacKey32, iv16, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-cbc', encKey32, iv16);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  const hmac = crypto.createHmac('sha256', hmacKey32);
  hmac.update(iv16);
  hmac.update(ciphertext);
  const mac = hmac.digest();

  return { ciphertext, mac }; // mac = 32 байта
}

function decryptCbcHmac(encKey32, hmacKey32, iv16, ciphertext, mac32) {
  // Сначала проверяем HMAC
  const hmac = crypto.createHmac('sha256', hmacKey32);
  hmac.update(iv16);
  hmac.update(ciphertext);
  const expectedMac = hmac.digest();

  if (!crypto.timingSafeEqual(mac32, expectedMac)) {
    throw new Error('HMAC validation failed — wrong password or corrupted data');
  }

  // Потом расшифровываем
  const decipher = crypto.createDecipheriv('aes-256-cbc', encKey32, iv16);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

module.exports = {
  deriveKey,
  randBytes,
  encryptCbcHmac,
  decryptCbcHmac
};