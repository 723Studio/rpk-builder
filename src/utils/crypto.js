'use strict';

const crypto = require('crypto');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

function deriveKey(passphrase, salt) {
  // returns 32-byte Buffer
  return crypto.scryptSync(passphrase, salt, 32, SCRYPT_PARAMS);
}

function randBytes(n) {
  return crypto.randomBytes(n);
}

function encryptAesGcm(key, iv, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext: enc, tag };
}

function decryptAesGcm(key, iv, ciphertext, tag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return dec;
}

module.exports = {
  deriveKey,
  randBytes,
  encryptAesGcm,
  decryptAesGcm
};