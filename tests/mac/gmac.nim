import ../../src/Cryptography/mac/gmac
import "../../src/Cryptography/block/aes"
import ./test_helpers
import ../../src/Cryptography/utils/digits

func aesGMAC(key, iv, input: openArray[uint8]): array[16, uint8] =
  gmacOne[AES128Ctx](aes128Init, aes128Encrypt, key, iv, input)

let key = fixedBytes[16]("00000000000000000000000000000000")
let iv = fixedBytes[12]("000000000000000000000000")
let empty: array[0, byte] = []
echo "AES GMAC Test"
echo "Key Standard : ", binToHex(key)
echo "IV Standard : ", binToHex(iv)
echo "Message Standard : "
let tag = aesGMAC(key, iv, empty)
echo "Result State : ", binToHex(tag)
echo "Result Standard : 58E2FCCEFA7E3061367F1D57A4E7455A"
doAssert tag == fixedBytes[16]("58e2fccefa7e3061367f1d57a4e7455a")
echo "AES-GMAC: OK"
