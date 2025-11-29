'use strict';

const fs = require('fs');
const path = require('path');
const { pack } = require('./pack');
const { randBytes } = require('./utils/crypto');

function usage() {
  console.error('Usage: node src/main.js <source_folder> <output_file> <passphrase>');
  process.exit(1);
}

if (process.argv.length < 5) usage();

const sourceFolder = path.resolve(process.argv[2]);
const outputFile = path.resolve(process.argv[3]);
const passphrase = process.argv[4];

if (!fs.existsSync(sourceFolder) || !fs.statSync(sourceFolder).isDirectory()) {
  console.error('Source folder not found:', sourceFolder);
  process.exit(1);
}

// Собрать список файлов рекурсивно
function collectFiles(dir, baseDir = dir) {
  let files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath);
    
    if (entry.isDirectory()) {
      files = files.concat(collectFiles(fullPath, baseDir));
    } else if (entry.isFile()) {
      files.push({ full: fullPath, rel: relPath });
    }
  }
  
  return files;
}

const fileList = collectFiles(sourceFolder);
if (fileList.length === 0) {
  console.error('No files found in source folder');
  process.exit(1);
}

console.log(`Found ${fileList.length} files to pack`);

const salt = randBytes(16);
const manifestIv = randBytes(12);

pack(fileList, salt, manifestIv, outputFile, passphrase);