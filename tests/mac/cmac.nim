import ../../src/Cryptography/mac/cmac
import "../../src/Cryptography/block/aes"
import ../../src/Cryptography/utils/digits
import ./test_helpers

let key = fixedBytes[16]("2b7e151628aed2a6abf7158809cf4f3c")
let message = fixedBytes[16]("6bc1bee22e409f96e93d7e117393172a")
let tag = cmacOne[AES128Ctx, 16](aes128Init, aes128Encrypt, key, message)
echo "AES-128 CMAC Test"
echo "Key Standard : ", binToHex(key)
echo "Message Standard : ", binToHex(message)
echo "Result State : ", binToHex(tag)
echo "Result Standard : 070A16B46B4D4144F79BDD9DD04A287C"
doAssert tag == fixedBytes[16]("070a16b46b4d4144f79bdd9dd04a287c"), "AES-CMAC Failed"
echo "AES-CMAC: OK"
