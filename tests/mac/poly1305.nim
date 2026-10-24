import ../../src/Cryptography/mac/poly1305
import ./test_helpers

let key = fixedBytes[32]("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
let message: seq[byte] = @[byte('C'), byte('r'), byte('y'), byte('p'), byte('t'), byte('o'), byte('g'), byte('r'), byte('a'), byte('p'), byte('h'), byte('i'), byte('c'), byte(' '), byte('F'), byte('o'), byte('r'), byte('u'), byte('m'), byte(' '), byte('R'), byte('e'), byte('s'), byte('e'), byte('a'), byte('r'), byte('c'), byte('h'), byte(' '), byte('G'), byte('r'), byte('o'), byte('u'), byte('p')]
doAssert poly1305One(key, message) == fixedBytes[16]("a8061dc1305136c6c22b8baf0c0127a9")
echo "Poly1305: OK"
