import "../../src/nim_cryptkit/block/aes"
import "../../src/nim_cryptkit/mode/ctr"
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
let iv = hexToBin("0011223344556677").value
let expected = "BCF192121EDEBC6AABB7515BBBF40457FE53A3AB"

# ============================================================
# Encryption Test
# ============================================================
var encCtx: CTRCtx[AES128Ctx, 16, 16, 8, 8]
ctrInit(aes128Init, encCtx, key, iv, BigEndian, 0)

let encPart1 = ctrInput(aes128Encrypt, encCtx, plaintext1)
let encPart2 = ctrInput(aes128Encrypt, encCtx, plaintext2)
let encFinal = ctrFinal(aes128Encrypt, encCtx)

let ciphertext = encPart1 & encPart2 & encFinal
let actualHex  = binToHex(ciphertext)

echo "=== AES-128-CTR Encryption ==="
echo "Plaintext  : ", binToHex(plaintext1), binToHex(plaintext2)
echo "Key        : ", binToHex(key)
echo "IV         : ", binToHex(iv)
echo "Ciphertext : ", actualHex
echo "Expected   : ", expected

doAssert actualHex == expected,
  "AES-128-CTR Encryption Mismatch! got=" & actualHex & " expected=" & expected

echo "Encryption Verification PASSED"

# ============================================================
# Decryption Round-trip Test
# ============================================================

var decCtx: CTRCtx[AES128Ctx, 16, 16, 8, 8]
ctrInit(aes128Init, decCtx, key, iv, BigEndian, 0)

let decPart1 = ctrInput(aes128Encrypt, decCtx, ciphertext)
let decResult = ctrFinal(aes128Encrypt, decCtx)

let recovered = decPart1 & decResult

echo ""
echo "=== AES-128-CTR Decryption ==="
echo "Recovered  : ", binToHex(recovered)
echo "Original   : ", binToHex(plaintext)

doAssert recovered == plaintext,
  "AES-128-CTR round-trip Mismatch! got=" & binToHex(recovered) & " expected=" & binToHex(plaintext)

echo "Decryption Round-trip PASSED"
