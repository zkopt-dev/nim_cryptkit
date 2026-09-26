import ../../src/Cryptography/kdf/scrypt
import ../../src/Cryptography/utils/digits
import helper

let emptyBytes: seq[uint8] = @[]

echo "scrypt RFC 7914 Test"
let scryptResult: seq[uint8] = scrypt(emptyBytes, emptyBytes, 16, 1, 1, 64)
echo "Result State : ", binToHex(scryptResult)
echo "Result Standard : 77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906"
doAssert scryptResult == hexToBin("77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906").value, "scrypt : Failed"
echo "scrypt: OK"
echo ""
