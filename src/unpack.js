'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const YAML = require('yaml');
const { deriveKey, decryptCbcHmac } = require('./utils/crypto');

const VERSION_EXPECTED = 3;

function usage() {
  console.error('Usage: node src/unpack.js <container_file> <output_folder> <passphrase>');
  process.exit(2);
}

if (process.argv.length < 5) usage();

const containerFile = path.resolve(process.argv[2]);
const outDir = path.resolve(process.argv[3]);
const passphrase = process.argv[4];

function ensureDirForFile(f) {
  const d = path.dirname(f);
  fs.mkdirSync(d, { recursive: true });
}

function readFixed(fd, pos, len) {
  const buf = Buffer.alloc(len);
  const read = fs.readSync(fd, buf, 0, len, pos);
  if (read !== len) throw new Error('Unable to read expected bytes');
  return buf;
}

function unpack() {
  if (!fs.existsSync(containerFile) || !fs.statSync(containerFile).isFile()) {
    console.error('Container file not found:', containerFile);
    process.exit(3);
  }

  const fd = fs.openSync(containerFile, 'r');
  try {
    let pos = 0;
    const magic = readFixed(fd, pos, 8);
    pos += 8;
    
    console.log('Magic bytes read:', magic);
    console.log('Magic expected:', Buffer.from('OXFTA1\0\0'));
    
    if (!magic.equals(Buffer.from('OXFTA1\0\0'))) {
      throw new Error('Bad magic');
    }
    const version = readFixed(fd, pos, 1).readUInt8(0);
    pos += 1;
    if (version !== VERSION_EXPECTED) throw new Error('Unsupported version: ' + version);

    // Header layout:
    // 0–7   : magic "OXFTA1\0\0"
    // 8     : version (1 byte)
    // 9–24  : salt (16)
    // 25–40 : manifest IV (16)
    // 41–44 : manifest encrypted length (4 bytes, unsigned BE)
    // 45... : encrypted manifest + MAC, then file blobs

    const salt = readFixed(fd, pos, 16);
    pos += 16;
    const ivMan = readFixed(fd, pos, 16);
    pos += 16;
    const lenMan = readFixed(fd, pos, 4).readUInt32BE(0);
    pos += 4;

    const encMan = readFixed(fd, pos, lenMan - 32);   // ciphertext
    pos += (lenMan - 32);
    const macMan = readFixed(fd, pos, 32);            // HMAC 32 байта
    pos += 32;

    const key = deriveKey(passphrase, salt);

    const manifestPlaintext = decryptCbcHmac(
      key.slice(0, 32),
      key.slice(32),
      ivMan,
      encMan,
      macMan
    );

    const manifest = YAML.parse(manifestPlaintext.toString('utf8'));

    // Небольшая защита от битых контейнеров
    if (!manifest?.files || !Array.isArray(manifest.files)) {
      throw new Error('Invalid or corrupted manifest: no files array');
    }

    const dataSectionStart = pos;

    for (const f of manifest.files) {
      const encLen = f.length;
      const encBuf = readFixed(fd, dataSectionStart + f.offset, encLen);
      if (encBuf.length < 32) throw new Error('Blob too small');
      const cipher = encBuf.slice(0, encBuf.length - 32);

      const iv = Buffer.from(f.iv, 'base64');
      const mac = Buffer.from(f.mac, 'base64');
      const plain = decryptCbcHmac(
        key.slice(0, 32),
        key.slice(32),
        iv,
        cipher,
        mac
      );

      let outBuf = plain;
      if (f.compressed) {
        outBuf = zlib.inflateSync(plain);
      }

      const outPath = path.join(outDir, f.path);
      ensureDirForFile(outPath);
      fs.writeFileSync(outPath, outBuf);
      console.log('Wrote', outPath);
    }

    console.log('Unpack finished.');
  } finally {
    fs.closeSync(fd);
  }
}

unpack();