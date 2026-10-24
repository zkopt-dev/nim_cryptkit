import ../../src/Cryptography/kdf/balloon
import ../../src/Cryptography/utils/digits
import helper

echo "Balloon Hashing Test"
let balloonPassword: seq[uint8] = hexToBin("70617373776F7264").value
let balloonSalt: seq[uint8] = hexToBin("73616C74").value
let balloonChangedSalt: seq[uint8] = hexToBin("73616C65").value
let balloonFirst = balloon(balloonPassword, balloonSalt, 8, 2, 2, 32)
let balloonChanged = balloon(balloonPassword, balloonChangedSalt, 8, 2, 2, 32)
echo "Password Standard : ", binToHex(balloonPassword)
echo "Salt Standard : ", binToHex(balloonSalt)
echo "Result State : ", binToHex(balloonFirst)
doAssert balloonFirst == balloon(balloonPassword, balloonSalt, 8, 2, 2, 32), "Balloon Determinism : Failed"
doAssert balloonFirst != balloonChanged, "Balloon Salt-Binding : Failed"
echo "Balloon: OK"
echo ""
