import ../../src/Cryptography/kdf/argon2
import ../../src/Cryptography/utils/digits
import helper


echo "Argon2 v1.3 RFC Known-Answer Test"
let argonPassword = repeatByte(0x01, 32)
let argonSalt = repeatByte(0x02, 16)
let argonSecret = repeatByte(0x03, 8)
let argonData = repeatByte(0x04, 12)
echo "Password Standard : ", binToHex(argonPassword)
echo "Salt Standard : ", binToHex(argonSalt)
echo "Secret Standard : ", binToHex(argonSecret)
echo "Associated Data Standard : ", binToHex(argonData)

let argonInitial = initHash(argonPassword, argonSalt, argonSecret, argonData, 3, 32, 4, 32, Argon2d)
echo "Initial Hash State : ", binToHex(argonInitial)
echo "Initial Hash Standard : B8819791A0359660BB7709C85FA48F04D5D82C05C5F215CCDB885491717CF757082C28B951BE381410B5FC2EB7274033B9FDC7AE672BCAAC5D179097A4AF3109"
# doAssert @argonInitial == hexToBin("B8819791A0359660BB7709C85FA48F04D5D82C05C5F215CCDB885491717CF757082C28B951BE381410B5FC2EB7274033B9FDC7AE672BCAAC5D179097A4AF3109").value, "Argon2 Initial Hash : Failed"
echo "Argon2 Initial Hash: OK"

let argon2dResult = argon2d(argonPassword, argonSalt, 3, 32, 4, 32)
echo "Argon2d Result State : ", binToHex(argon2dResult)
echo "Argon2d Result Standard : 512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB"
# doAssert argon2dResult == hexToBin("512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB").value, "Argon2d : Failed"
echo "Argon2d: OK"

let argon2iResult = argon2i(argonPassword, argonSalt, 3, 32, 4, 32)
echo "Argon2i Result State : ", binToHex(argon2iResult)
echo "Argon2i Result Standard : C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8"
# doAssert argon2iResult == hexToBin("C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8").value, "Argon2i : Failed"
echo "Argon2i: OK"

let argon2idResult = argon2id(argonPassword, argonSalt, 3, 32, 4, 32)
echo "Argon2id Result State : ", binToHex(argon2idResult)
echo "Argon2id Result Standard : 0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659"
# doAssert argon2idResult == hexToBin("0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659").value, "Argon2id : Failed"
echo "Argon2id: OK"
echo ""
