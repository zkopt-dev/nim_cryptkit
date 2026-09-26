import "../../src/nim_cryptkit/block/aes"
import "../../src/nim_cryptkit/mode/cbc"
import "../../src/nim_cryptkit/mode/padding"
import "../../src/nim_cryptkit/utils/digits"
import "../../src/nim_cryptkit/utils/errorutils"
import std/[monotimes, times]

# ============================================================
# Test Vector (CyberChef AES-128-CBC + PKCS#7)
# ============================================================
let plaintext1 = hexToBin("0AEA02838D8382838D838D83").value
let plaintext2 = hexToBin("8F8392349500039A").value
let plaintext = hexToBin("0AEA02838D8382838D838D838F8392349500039A").value
let key = hexToBin("000102030405060708090A0B0C0D0E0F").value
let iv = hexToBin("00112233445566778899AABBCCDDEEFF").value
let expected = "DF4B722E061524BB043762BE16A6393EDD054AAF48AFE46E0BE4DD45B61DB82D"

# ============================================================
# Encryption Test
# ============================================================
var encCtx: CBCCtx[AES128Ctx, 16, 16]
cbcEncryptInit(aes128Init, encCtx, key, iv)

let encPart1 = cbcEncryptInput(aes128Encrypt, encCtx, plaintext1)
let encPart2 = cbcEncryptInput(aes128Encrypt, encCtx, plaintext2)
let encFinal = cbcEncryptFinal(aes128Encrypt, pkcs7, encCtx)

let ciphertext = encPart1 & encPart2 & encFinal
let actualHex  = binToHex(ciphertext)

echo "=== AES-128-CBC PKCS#7 Encryption ==="
echo "Plaintext  : ", binToHex(plaintext1), binToHex(plaintext2)
echo "Key        : ", binToHex(key)
echo "IV         : ", binToHex(iv)
echo "Ciphertext : ", actualHex
echo "Expected   : ", expected

doAssert actualHex == expected,
  "AES-128-CBC Encryption Mismatch! got=" & actualHex & " expected=" & expected

echo "Encryption Verification PASSED"

# ============================================================
# Decryption Round-trip Test
# ============================================================

var decCtx: CBCCtx[AES128Ctx, 16, 16]
cbcDecryptInit(aes128Init, decCtx, key, iv)

let decPart1 = cbcDecryptInput(aes128Decrypt, decCtx, ciphertext)
let decResult = cbcDecryptFinal(aes128Decrypt, unpkcs7, decCtx)

doAssert decResult.kind == Success, "AES-128-CBC Decryption Failed!"
let recovered = decPart1 & decResult.value

echo ""
echo "=== AES-128-CBC PKCS#7 Decryption ==="
echo "Recovered  : ", binToHex(recovered)
echo "Original   : ", binToHex(plaintext)

doAssert recovered == plaintext,
  "AES-128-CBC Round-trip Mismatch! got=" & binToHex(recovered) & " expected=" & binToHex(plaintext)

echo "Decryption Round-trip PASSED"
