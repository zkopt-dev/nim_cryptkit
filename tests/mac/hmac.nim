import ../../src/Cryptography/mac/hmac
import ../../src/Cryptography/hash/sha2
import ./test_helpers
import ../../src/Cryptography/utils/digits

let key = fixedBytes[20]("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
let message: seq[byte] = @[byte('H'), byte('i'), byte(' '), byte('T'), byte('h'), byte('e'), byte('r'), byte('e')]
echo "SHA-256 HMAC Test"
echo "Key Standard : ", binToHex(key)
echo "Message Standard : ", binTOHex(message)
let tag = hmacOne[SHA2_256Ctx, 64, 32](sha2_256Init, sha2_256Input, sha2_256Final, key, message)
echo "Result State : ", binToHex(tag)
echo "Result Standard : B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7"
doAssert tag == fixedBytes[32]("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
echo "HMAC-SHA-256: OK"
