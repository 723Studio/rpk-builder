'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const YAML = require('yaml');
const { deriveKey, randBytes, encryptAesGcm } = require('./utils/crypto');

const MAGIC = Buffer.from('OXFTA1\0\0');
const VERSION = Buffer.from([2]);

function shouldCompressByExt(filename) {
  const compressible = ['.txt', '.json', '.rul', '.yaml', '.yml', '.js', '.css', '.html', '.svg'];
  const ext = path.extname(filename).toLowerCase();
  return compressible.includes(ext);
}

function pack(fileList, salt, manifestIv, outFile, passphrase) {
  const key = deriveKey(passphrase, salt);

  console.log('Pack: Passphrase:', passphrase);
  console.log('Pack: Salt (hex):', salt.toString('hex'));
  console.log('Pack: Manifest IV (hex):', manifestIv.toString('hex'));
  console.log('Pack: Derived Key (hex):', key.toString('hex'));

  const fileBlobs = [];
  let dataOffset = 0;


  for (const fi of fileList) {
    const raw = fs.readFileSync(fi.full);
    let payload = raw;
    let compressed = false;
    if (shouldCompressByExt(fi.rel)) {
      try {
        const def = zlib.deflateSync(raw, { level: 9 });
        if (def.length + 8 < raw.length) { // require at least 8-byte save
          payload = def;
          compressed = true;
        }
      } catch (e) {
        // ignore compression errors
      }
    }


    const iv = randBytes(12);
    const { ciphertext, tag } = encryptAesGcm(key, iv, payload);
    // store ciphertext + tag as blob
    const blob = Buffer.concat([ciphertext, tag]);
    fileBlobs.push({
      path: fi.rel,
      offset: dataOffset,
      length: blob.length,
      compressed,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      blob
    });
    dataOffset += blob.length;
  }


  const manifestObj = { 
    files: fileBlobs.map(b => ({ 
      path: b.path, 
      offset: b.offset, 
      length: b.length, 
      compressed: b.compressed, 
      iv: b.iv, 
      tag: b.tag 
    })) 
  };

  // YAML.stringify даёт строку, сразу превращаем в Buffer
  const manifestYaml = Buffer.from(YAML.stringify(manifestObj), 'utf8');

  // encrypt manifest with same key + manifestIv
  const { ciphertext: encMan, tag: tagMan } = encryptAesGcm(key, manifestIv, manifestYaml);
  console.log('Pack: Encrypted manifest length:', encMan.length);
  console.log('Pack: Tag (hex):', tagMan.toString('hex'));

  // write container
  const outFd = fs.openSync(outFile, 'w');
  try {
    // header
    console.log('Writing magic:', MAGIC);
    console.log('Writing version:', VERSION);
    
    fs.writeSync(outFd, MAGIC);
    fs.writeSync(outFd, VERSION);
    fs.writeSync(outFd, salt);
    fs.writeSync(outFd, manifestIv);


    const manifestLength = Buffer.alloc(4);
    manifestLength.writeUInt32BE(encMan.length + 16, 0); // include tag length
    fs.writeSync(outFd, manifestLength);


    fs.writeSync(outFd, encMan);
    fs.writeSync(outFd, tagMan);


    for (const fb of fileBlobs) {
      fs.writeSync(outFd, fb.blob);
    }
    console.log('Wrote container to', outFile);
  } finally {
    fs.closeSync(outFd);
  }
}

module.exports = { pack };
