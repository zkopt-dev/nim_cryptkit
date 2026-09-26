import ../../src/Cryptography/mac/cbcmac
import "../../src/Cryptography/block/aes"
import ./test_helpers
import ../../src/Cryptography/utils/digits

proc noPadding(input: openArray[byte]; inputLen, blockSize: int): seq[byte] =
  doAssert inputLen mod blockSize == 0
  result = newSeq[byte](inputLen)
  for i in 0..<inputLen: result[i] = input[i]

let key = fixedBytes[16]("2b7e151628aed2a6abf7158809cf4f3c")
let message = fixedBytes[16]("6bc1bee22e409f96e93d7e117393172a")
var ctx: CBCMACCtx[AES128Ctx, 16]

echo "AES-128 CBCMAC Test"
echo "Key Standard : ", binToHex(key)
echo "Message Standard : ", binToHex(message)
cbcmacInit(ctx, aes128Init, key)
cbcmacInput(ctx, aes128Encrypt, message)
let empty: array[0, byte] = []
let result = cbcmacFinal(ctx, aes128Encrypt, noPadding)
echo "Result State : ", binToHex(result)
echo "Result Standard : 3AD77BB40D7A3660A89ECAF32466EF97"
doAssert result == fixedBytes[16]("3ad77bb40d7a3660a89ecaf32466ef97"), "AES-CBCMAC : Failed"
echo "AES-CBCMAC: OK"
