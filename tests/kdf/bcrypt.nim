import ../../src/Cryptography/kdf/bcrypt
import ../../src/Cryptography/utils/digits
import helper

echo "bcrypt OpenBSD Test"
let bcryptPassword: seq[uint8] = charToBin("allmine".toOpenArray(0, 6))
let bcryptSalt: seq[uint8] = bcryptBase64Decode("XajjQvNhvvRt5GSeFk1xFe")
echo "Salt Standard : XajjQvNhvvRt5GSeFk1xFe"
let bcryptResult: string = bcrypt(bcryptPassword, bcryptSalt, 10)
echo "Result State : ", bcryptResult
echo "Result Standard : $2b$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"
doAssert bcryptResult == "$2b$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga", "bcrypt : Failed"
echo "bcrypt: OK"
echo ""
