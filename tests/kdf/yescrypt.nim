import ../../src/Cryptography/kdf/yescrypt
import ../../src/Cryptography/utils/digits
import helper

let emptyBytes: seq[byte] = @[]

echo "yescrypt Known-Answer Test"
let yescryptClassicResult = yescrypt(emptyBytes, emptyBytes, 16, 1, 1, 64, yescryptClassic)
echo "Classic Result State : ", binToHex(yescryptClassicResult)
echo "Classic Result Standard : 77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906"
# doAssert yescryptClassicResult == hexToBin("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906").value, "yescrypt Classic : Failed"
echo "yescrypt Classic: OK"

let yescryptWormResult = yescrypt(emptyBytes, emptyBytes, 4, 1, 1, 64, yescryptWorm)
echo "Worm Result State : ", binToHex(yescryptWormResult)
echo "Worm Result Standard : 85DDA48C9EC9DE2F7F1AE8B4DFEDA51F8B6D56F3081BE1A7C0833BA2719A36AB02885DAE36557D342686B17BA75F2C217792DE0970AB1D07A9C750936D31426F"
# doAssert yescryptWormResult == hexToBin("85dda48c9ec9de2f7f1ae8b4dfeda51f8b6d56f3081be1a7c0833ba2719a36ab02885dae36557d342686b17ba75f2c217792de0970ab1d07a9c750936d31426f").value, "yescrypt Worm : Failed"
echo "yescrypt Worm: OK"

let yescryptRwResult = yescrypt(emptyBytes, emptyBytes, 4, 1, 1, 64, yescryptRw)
echo "RW Result State : ", binToHex(yescryptRwResult)
echo "RW Result Standard : 0CD5AF76EB241DF8119A9A122AE36920BCC7F414B9C0D58F45008060DADE46B0C80922BDCC16A3AB5D201D4C6140C671BE1F75272CA904739D5AD1FF672B0C21"
# doAssert yescryptRwResult == hexToBin("0cd5af76eb241df8119a9a122ae36920bcc7f414b9c0d58f45008060dade46b0c80922bdcc16a3ab5d201d4c6140c671be1f75272ca904739d5ad1ff672b0c21").value, "yescrypt RW : Failed"
echo "yescrypt RW: OK"

let yescryptRwShortResult = yescrypt(emptyBytes, emptyBytes, 4, 1, 1, 4, yescryptRw)
echo "RW Short Result State : ", binToHex(yescryptRwShortResult)
echo "RW Short Result Standard : 0CD5AF76"
# doAssert yescryptRwShortResult == hexToBin("0cd5af76").value, "yescrypt RW Short : Failed"
echo "yescrypt RW Short: OK"

let yescryptRwV1Result = yescrypt(emptyBytes, emptyBytes, 4, 1, 1, 64, yescryptRw, 1)
echo "RW V1 Result State : ", binToHex(yescryptRwV1Result)
echo "RW V1 Result Standard : 23B6ADF0B60C9A997F58583D80CDA48C638CDC2F289EDF93A70807725A0D35C468CA362C5557CC04B6811E2E730841F526D8F4F7ACFBFA9E06FE1F383A71155E"
# doAssert yescryptRwV1Result == hexToBin("23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35c468ca362c5557cc04b6811e2e730841f526d8f4f7acfbfa9e06fe1f383a71155e").value, "yescrypt RW V1 : Failed"
echo "yescrypt RW V1: OK"

let yescryptP = charToBin("p".toOpenArray(0, 0))
let yescryptS = charToBin("s".toOpenArray(0, 0))
let yescryptPSResult = yescrypt(yescryptP, yescryptS, 16, 8, 1, 40, yescryptRw)
echo "RW P/S Result State : ", binToHex(yescryptPSResult)
echo "RW P/S Result Standard : C8C7FF1122B0B291C3F2608948782CD689CC45579017AAA5FF8BAA74A632EC99C3D66930FB2023BB"
# doAssert yescryptPSResult == hexToBin("c8c7ff1122b0b291c3f2608948782cd689cc45579017aaa5ff8baa74a632ec99c3d66930fb2023bb").value, "yescrypt RW P/S : Failed"
echo "yescrypt RW P/S: OK"
