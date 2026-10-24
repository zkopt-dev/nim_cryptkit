import ../../src/Cryptography/kdf/pbkdf2
import ../../src/Cryptography/utils/digits
import helper

echo "PBKDF2-HMAC-SHA-256 Test"
let pbkdf2Password = charToBin("password".toOpenArray(0, 7))
let pbkdf2Salt = charToBin("salt".toOpenArray(0, 3))
echo "Password Standard : ", binToHex(pbkdf2Password)
echo "Salt Standard : ", binToHex(pbkdf2Salt)
let pbkdf2Sha256Result = pbkdf2SHA256(pbkdf2Password, pbkdf2Salt, 1, 32)
echo "Result State : ", binToHex(pbkdf2Sha256Result)
echo "Result Standard : 120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B"
doAssert pbkdf2Sha256Result == hexToBin("120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B").value, "PBKDF2-HMAC-SHA-256 : Failed"
echo "PBKDF2-HMAC-SHA-256: OK"
echo ""

echo "PBKDF2-HMAC-SHA-512 Test"
echo "Password Standard : ", binToHex(pbkdf2Password)
echo "Salt Standard : ", binToHex(pbkdf2Salt)
let pbkdf2Sha512Result = pbkdf2SHA512(pbkdf2Password, pbkdf2Salt, 1, 64)
echo "Result State : ", binToHex(pbkdf2Sha512Result)
echo "Result Standard : 867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE"
doAssert pbkdf2Sha512Result == hexToBin("867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE").value, "PBKDF2-HMAC-SHA-512 : Failed"
echo "PBKDF2-HMAC-SHA-512: OK"
echo ""
