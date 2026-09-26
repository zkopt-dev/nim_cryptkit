import ../../src/Cryptography/kdf/catena
import ../../src/Cryptography/utils/digits
import helper

echo "Catena Dragonfly-Full Test"
let catenaPassword = charToBin("password".toOpenArray(0, 7))
let catenaSalt = charToBin("salt".toOpenArray(0, 3))
echo "Password Standard : ", binToHex(catenaPassword)
echo "Salt Standard : ", binToHex(catenaSalt)
let catenaResult = catena(catenaPassword, catenaSalt, 1)
echo "Result State : ", binToHex(catenaResult)
echo "Result Standard : 7DAEE388A3B2252F40B60A447D2972659E33278DEBB2F0EC3F91F004AEE9946A68E44F7DFC39A453CBC350EDD068E45BD77087B7A5DA73690FA17C88961B1596"
doAssert catenaResult == hexToBin("7DAEE388A3B2252F40B60A447D2972659E33278DEBB2F0EC3F91F004AEE9946A68E44F7DFC39A453CBC350EDD068E45BD77087B7A5DA73690FA17C88961B1596").value, "Catena : Failed"
echo "Catena: OK"
echo ""
