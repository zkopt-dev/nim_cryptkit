import "../../src/nim_cryptkit/block/aes"
import "../../src/nim_cryptkit/mode/ecb"
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
let expected = "22D3223DE1296D1F9B48B58747EC8D36A020FC69E7B2104A45DB16FFDDF9DA4B"

# ============================================================
# Encryption Test
# ============================================================
var encCtx: ECBCtx[AES128Ctx, 16, 16]
ecbEncryptInit(aes128Init, encCtx, key)

let encPart1 = ecbEncryptInput(aes128Encrypt, encCtx, plaintext1)
let encPart2 = ecbEncryptInput(aes128Encrypt, encCtx, plaintext2)
let encFinal = ecbEncryptFinal(aes128Encrypt, pkcs7, encCtx)

let ciphertext = encPart1 & encPart2 & encFinal
let actualHex  = binToHex(ciphertext)

echo "=== AES-128-ECB PKCS#7 Encryption ==="
echo "Plaintext  : ", binToHex(plaintext1), binToHex(plaintext2)
echo "Key        : ", binToHex(key)
echo "Ciphertext : ", actualHex
echo "Expected   : ", expected

doAssert actualHex == expected,
  "AES-128-ECB Encryption Mismatch! got=" & actualHex & " expected=" & expected

echo "Encryption Verification PASSED"

# ============================================================
# Decryption Round-trip Test
# ============================================================

var decCtx: ECBCtx[AES128Ctx, 16, 16]
ecbDecryptInit(aes128Init, decCtx, key)

let decPart1 = ecbDecryptInput(aes128Decrypt, decCtx, ciphertext)
let decResult = ecbDecryptFinal(aes128Decrypt, unpkcs7, decCtx)

doAssert decResult.kind == Success, "AES-128-ECB Decryption Failed!"
let recovered = decPart1 & decResult.value

echo ""
echo "=== AES-128-ECB PKCS#7 Decryption ==="
echo "Recovered  : ", binToHex(recovered)
echo "Original   : ", binToHex(plaintext)

doAssert recovered == plaintext,
  "AES-128-ECB Round-trip Mismatch! got=" & binToHex(recovered) & " expected=" & binToHex(plaintext)

echo "Decryption Round-trip PASSED"
