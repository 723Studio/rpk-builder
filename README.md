/*
OXC_FTA Packer
============


This project contains a Node.js CLI packer/unpacker for the OXFTA container format
(designed for the "X-Com From The Ashes" project). The packer compresses (optionally)
and encrypts files and stores them in a single binary container. The manifest (paths,
offsets, lengths, ivs, etc.) is also encrypted so the internal structure is hidden.


Container format summary
------------------------
HEADER (fixed-size fields)
- MAGIC[8] = ASCII "OXFTA1\0\0\0" (8 bytes)
- VERSION[1] = 0x01
- SALT[16] = random bytes for KDF
- IV_MANIFEST[12] = IV for AES-GCM that encrypts the manifest
- MANIFEST_LENGTH[4] = big-endian uint32 length of (manifest_enc + tag)


MANIFEST_ENCRYPTED
- AES-256-GCM encrypted JSON manifest (manifest_enc) followed by 16-byte auth tag


DATA SECTION
- Sequence of file blobs; each blob = ciphertext + 16-byte auth tag
- Manifest entries contain for each file: path, offset (relative to data section start), length (bytes in container), compressed (bool), iv (base64), tag (base64)


Crypto details
--------------
- Key derivation: scrypt(passphrase, salt, 32)
- File encryption: AES-256-GCM
- Per-file IV: 12 bytes random (base64 in manifest)
- Tag: 16 bytes appended to encrypted blob
- Manifest encrypted using same derived key with its own IV (12 bytes) and tag appended


Usage
-----
- Pack: node src/pack.js <input_folder> <output_container> <passphrase>
- Unpack: node src/unpack.js <container_file> <output_folder> <passphrase>


Notes and recommendations
-------------------------
- No external npm packages are used (only built-in modules).
- The packer will attempt to compress YAML/JSON/TXT/XML files; compression used only if it reduces the size by at least 8 bytes.
- For development convenience, add a "dev" mode later where filesystem is preferred over container for easy modding.



*/