import ../../src/Cryptography/kdf/nthash
import ../../src/Cryptography/utils/digits
import helper

echo "NT Hash Test"
let ntResult = ntHash("password")
echo "Password Standard : password"
echo "Result State : ", binToHex(ntResult)
echo "Result Standard : 8846F7EAEE8FB117AD06BDD830B7586C"
doAssert ntResult == fixedBytes[16]("8846f7eaee8fb117ad06bdd830b7586c"), "NT Hash : Failed"
echo "NT Hash: OK"
echo ""

echo "LM Hash Test"
let lmResult = lmHash("PASSWORD")
echo "Password Standard : PASSWORD"
echo "Result State : ", binToHex(lmResult)
echo "Result Standard : E52CAC67419A9A224A3B108F3FA6CB6D"
doAssert lmResult == fixedBytes[16]("e52cac67419a9a224a3b108f3fa6cb6d"), "LM Hash : Failed"
echo "LM Hash: OK"
echo ""
