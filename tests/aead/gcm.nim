import "../../src/nim_cryptkit/block/aes"
import "../../src/nim_cryptkit/aead/gcm"
import "../../src/nim_cryptkit/utils/digits"
import "../../src/nim_cryptkit/utils/errorutils"
import "./test_helpers"
import std/strutils

# ============================================================
# AES-GCM official test vectors
#   * NIST "Block Cipher Modes of Operation: GCM" example file
#     (csrc.nist.gov/.../Examples/AES_GCM.txt)
#   * "The Galois/Counter Mode of Operation (GCM)" by McGrew &
#     Viega (the GCM specification, Appendix B test cases)
# ============================================================

var passed = 0

template gcmVector(C, init, encrypt: untyped, tagLen: static int,
                   name, keyHex, ivHex, aadHex, ptHex, ctHex, tagHex: string) =
  block:
    let key = hexBytes(keyHex)
    let iv = hexBytes(ivHex)
    let aad = hexBytes(aadHex)
    let pt = hexBytes(ptHex)

    let (ct, tag) = gcmEncryptOne[C, 16, 16, 12, 4](init, encrypt, key, iv, aad, pt, tagLen)
    doAssert sameHex(binToHex(ct), ctHex),
      name & " ciphertext mismatch: got " & binToHex(ct) & " want " & ctHex
    doAssert sameHex(binToHex(tag), tagHex),
      name & " tag mismatch: got " & binToHex(tag) & " want " & tagHex

    let res = gcmDecryptOne[C, 16, 16, 12, 4](init, encrypt, key, iv, aad, ct, tag, tagLen)
    doAssert res.kind == Success, name & " decrypt failed"
    doAssert sameHex(binToHex(res.value), ptHex),
      name & " decrypt mismatch: got " & binToHex(res.value) & " want " & ptHex

    # Wrong tag must be rejected.
    var badTag = tag
    badTag[0] = badTag[0] xor 0x01
    let bad = gcmDecryptOne[C, 16, 16, 12, 4](init, encrypt, key, iv, aad, ct, badTag, tagLen)
    doAssert bad.kind == Failure, name & " accepted forged tag"

    inc passed

# ------------------------------------------------------------
# AES-128 (GCM specification test cases 1-6)
# ------------------------------------------------------------
gcmVector(AES128Ctx, aes128Init, aes128Encrypt, 16, "AES-128 TC1",
  "00000000000000000000000000000000",
  "000000000000000000000000",
  "",
  "",
  "",
  "58e2fccefa7e3061367f1d57a4e7455a")

gcmVector(AES128Ctx, aes128Init, aes128Encrypt, 16, "AES-128 TC2",
  "00000000000000000000000000000000",
  "000000000000000000000000",
  "",
  "00000000000000000000000000000000",
  "0388dace60b6a392f328c2b971b2fe78",
  "ab6e47d42cec13bdf53a67b21257bddf")

gcmVector(AES128Ctx, aes128Init, aes128Encrypt, 16, "AES-128 TC3",
  "feffe9928665731c6d6a8f9467308308",
  "cafebabefacedbaddecaf888",
  "",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
  "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
  "4d5c2af327cd64a62cf35abd2ba6fab4")

gcmVector(AES128Ctx, aes128Init, aes128Encrypt, 16, "AES-128 TC4",
  "feffe9928665731c6d6a8f9467308308",
  "cafebabefacedbaddecaf888",
  "feedfacedeadbeeffeedfacedeadbeefabaddad2",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
  "5bc94fbc3221a5db94fae95ae7121a47")

# TC5 / TC6 exercise non-96-bit IVs (8-byte and 60-byte).
gcmVector(AES128Ctx, aes128Init, aes128Encrypt, 16, "AES-128 TC5",
  "feffe9928665731c6d6a8f9467308308",
  "cafebabefacedbad",
  "feedfacedeadbeeffeedfacedeadbeefabaddad2",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
  "3612d2e79e3b0785561be14aaca2fccb")

gcmVector(AES128Ctx, aes128Init, aes128Encrypt, 16, "AES-128 TC6",
  "feffe9928665731c6d6a8f9467308308",
  "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
  "feedfacedeadbeeffeedfacedeadbeefabaddad2",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
  "619cc5aefffe0bfa462af43c1699d050")

# ------------------------------------------------------------
# NIST AES_GCM.txt example #6 uses a 96-bit tag.
# ------------------------------------------------------------
gcmVector(AES128Ctx, aes128Init, aes128Encrypt, 12, "NIST AES-GCM Ex6 (96-bit tag)",
  "feffe9928665731c6d6a8f9467308308",
  "cafebabefacedbaddecaf888",
  "3ad77bb40d7a3660a89ecaf32466ef97f5d3d585",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
  "f07c2528eea2fca1211f905e")

# ------------------------------------------------------------
# AES-192 (test cases 7-10)
# ------------------------------------------------------------
gcmVector(AES192Ctx, aes192Init, aes192Encrypt, 16, "AES-192 TC7",
  "000000000000000000000000000000000000000000000000",
  "000000000000000000000000",
  "",
  "",
  "",
  "cd33b28ac773f74ba00ed1f312572435")

gcmVector(AES192Ctx, aes192Init, aes192Encrypt, 16, "AES-192 TC8",
  "000000000000000000000000000000000000000000000000",
  "000000000000000000000000",
  "",
  "00000000000000000000000000000000",
  "98e7247c07f0fe411c267e4384b0f600",
  "2ff58d80033927ab8ef4d4587514f0fb")

gcmVector(AES192Ctx, aes192Init, aes192Encrypt, 16, "AES-192 TC9",
  "feffe9928665731c6d6a8f9467308308feffe9928665731c",
  "cafebabefacedbaddecaf888",
  "",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
  "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
  "9924a7c8587336bfb118024db8674a14")

gcmVector(AES192Ctx, aes192Init, aes192Encrypt, 16, "AES-192 TC10",
  "feffe9928665731c6d6a8f9467308308feffe9928665731c",
  "cafebabefacedbaddecaf888",
  "feedfacedeadbeeffeedfacedeadbeefabaddad2",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
  "2519498e80f1478f37ba55bd6d27618c")

# ------------------------------------------------------------
# AES-256 (test cases 13-16)
# ------------------------------------------------------------
gcmVector(AES256Ctx, aes256Init, aes256Encrypt, 16, "AES-256 TC13",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "000000000000000000000000",
  "",
  "",
  "",
  "530f8afbc74536b9a963b4f1c4cb738b")

gcmVector(AES256Ctx, aes256Init, aes256Encrypt, 16, "AES-256 TC14",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "000000000000000000000000",
  "",
  "00000000000000000000000000000000",
  "cea7403d4d606b6e074ec5d3baf39d18",
  "d0d1c8a799996bf0265b98b5d48ab919")

gcmVector(AES256Ctx, aes256Init, aes256Encrypt, 16, "AES-256 TC15",
  "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
  "cafebabefacedbaddecaf888",
  "",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
  "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
  "b094dac5d93471bdec1a502270e3cc6c")

gcmVector(AES256Ctx, aes256Init, aes256Encrypt, 16, "AES-256 TC16",
  "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
  "cafebabefacedbaddecaf888",
  "feedfacedeadbeeffeedfacedeadbeefabaddad2",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
  "76fc6ece0f4e1768cddf8853bb2d551b")

echo ""
echo "AES-GCM: ", passed, " vectors passed"
