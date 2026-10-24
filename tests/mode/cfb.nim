import "../../src/nim_cryptkit/block/aes"
import "../../src/nim_cryptkit/mode/cfb"
import "../../src/nim_cryptkit/mode/padding"
import "../../src/nim_cryptkit/utils/digits"
import "../../src/nim_cryptkit/utils/errorutils"
import std/[monotimes, times]

# ============================================================
# Test Vector (CyberChef AES-128-CFB)
# ============================================================
let plaintext1 = hexToBin("0AEA02838D8382838D838D83").value
let plaintext2 = hexToBin("8F8392349500039A").value
let plaintext = hexToBin("0AEA02838D8382838D838D838F8392349500039A").value
let key = hexToBin("000102030405060708090A0B0C0D0E0F").value
let iv = hexToBin("00112233445566778899AABBCCDDEEFF").value
let expected = "632EE25BE7F886B3554E3A03FF37576E0AC526CF"

# ============================================================
# Encryption Test
# ============================================================
var encCtx: CFBCtx[AES128Ctx, 16, 16]
cfbEncryptInit(aes128Init, encCtx, key, iv)

let encPart1 = cfbEncryptInput(aes128Encrypt, encCtx, plaintext1)
let encPart2 = cfbEncryptInput(aes128Encrypt, encCtx, plaintext2)
let encFinal = cfbEncryptFinal(aes128Encrypt, encCtx)

let ciphertext = encPart1 & encPart2 & encFinal
let actualHex  = binToHex(ciphertext)

echo "=== AES-128-CFB Encryption ==="
echo "Plaintext  : ", binToHex(plaintext1), binToHex(plaintext2)
echo "Key        : ", binToHex(key)
echo "IV         : ", binToHex(iv)
echo "Ciphertext : ", actualHex
echo "Expected   : ", expected

doAssert actualHex == expected,
  "AES-128-CFB Encryption Mismatch! got=" & actualHex & " expected=" & expected

echo "Encryption Verification PASSED"

# ============================================================
# Decryption Round-trip Test
# ============================================================

var decCtx: CFBCtx[AES128Ctx, 16, 16]
cfbDecryptInit(aes128Init, decCtx, key, iv)

let decPart1 = cfbDecryptInput(aes128Encrypt, decCtx, ciphertext)
let decResult = cfbDecryptFinal(aes128Encrypt, decCtx)

let recovered = decPart1 & decResult

echo ""
echo "=== AES-128-CFB Decryption ==="
echo "Recovered  : ", binToHex(recovered)
echo "Original   : ", binToHex(plaintext)

doAssert recovered == plaintext,
  "AES-128-CFB round-trip Mismatch! got=" & binToHex(recovered) & " expected=" & binToHex(plaintext)

echo "Decryption Round-trip PASSED"
