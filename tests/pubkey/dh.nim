import ../../src/Cryptography/pubkey/[dh, fixedint, common]
import ../../src/Cryptography/utils/[envconst, digits]

# -----------------------------------------------------------------------------
# Deterministic RNG — Alice secret = 2, Bob secret = 3
# -----------------------------------------------------------------------------
var aliceCalls = 0
proc aliceRng(output: var openArray[uint8]) {.gcsafe, raises: [].} =
  for i in 0 ..< output.len: output[i] = 0
  output[output.high] = 2
  inc aliceCalls

var bobCalls = 0
proc bobRng(output: var openArray[uint8]) {.gcsafe, raises: [].} =
  for i in 0 ..< output.len: output[i] = 0
  output[output.high] = 3
  inc bobCalls

# -----------------------------------------------------------------------------
# DH2048 Deterministic Key Exchange
# -----------------------------------------------------------------------------
echo "DH2048 Deterministic Key Exchange"

aliceCalls = 0
bobCalls = 0

var alice: DH2048Ctx
alice.dh2048Init(aliceRng)

var bob: DH2048Ctx
bob.dh2048Init(bobRng)

echo "Alice Private Key : ", binToHex(alice.privateKey.data)
echo "Alice Public Key  : ", binToHex(alice.publicKey.data)
echo "Bob Private Key   : ", binToHex(bob.privateKey.data)
echo "Bob Public Key    : ", binToHex(bob.publicKey.data)

let aliceSecret: DH2048SharedSecret = alice.dh2048Derive(bob.publicKey)
let bobSecret: DH2048SharedSecret = bob.dh2048Derive(alice.publicKey)

echo "Alice Shared Secret : ", binToHex(aliceSecret)
echo "Bob Shared Secret   : ", binToHex(bobSecret)

doAssert aliceSecret == bobSecret, "DH2048 Shared Secret : Mismatch"
echo "DH2048 Shared Secret : OK"
echo ""

# -----------------------------------------------------------------------------
# DH2048 Determinism Check — same keys → same secret
# -----------------------------------------------------------------------------
echo "DH2048 Determinism Check"

aliceCalls = 0
bobCalls = 0

var alice2: DH2048Ctx
alice2.dh2048Init(aliceRng)

var bob2: DH2048Ctx
bob2.dh2048Init(bobRng)

let aliceSecret2: DH2048SharedSecret = alice2.dh2048Derive(bob2.publicKey)
let bobSecret2: DH2048SharedSecret = bob2.dh2048Derive(alice2.publicKey)

doAssert aliceSecret == aliceSecret2, "DH2048 Determinism : Alice Mismatch"
doAssert bobSecret == bobSecret2, "DH2048 Determinism : Bob Mismatch"
echo "DH2048 Determinism : OK"
echo ""

# -----------------------------------------------------------------------------
# DH2048 Tampered Public Key Detection
# -----------------------------------------------------------------------------
echo "DH2048 Tampered Public Key Detection"

var tamperedPub: DH2048PublicKey
tamperedPub.data = Modp2048P
tamperedPub.data[0] -= 1

let tamperedValid: bool = alice.parameters.dhValidatePublicKey(tamperedPub)
doAssert not tamperedValid, "DH2048 Tampered Public Key : Should Fail"
echo "DH2048 Tampered Public Key : OK"
echo ""

# -----------------------------------------------------------------------------
# DH3072 Deterministic Key Exchange
# -----------------------------------------------------------------------------
echo "DH3072 Deterministic Key Exchange"

aliceCalls = 0
bobCalls = 0

var alice3072: DH3072Ctx
alice3072.dh3072Init(aliceRng)

var bob3072: DH3072Ctx
bob3072.dh3072Init(bobRng)

echo "Alice Private Key : ", binToHex(alice3072.privateKey.data)
echo "Bob Private Key   : ", binToHex(bob3072.privateKey.data)

let aliceSecret3072: DH3072SharedSecret = alice3072.dh3072Derive(bob3072.publicKey)
let bobSecret3072: DH3072SharedSecret = bob3072.dh3072Derive(alice3072.publicKey)

echo "Alice Shared Secret : ", binToHex(aliceSecret3072)
echo "Bob Shared Secret   : ", binToHex(bobSecret3072)

doAssert aliceSecret3072 == bobSecret3072, "DH3072 Shared Secret : Mismatch"
echo "DH3072 Shared Secret : OK"
echo ""

# -----------------------------------------------------------------------------
# DH4096 Deterministic Key Exchange
# -----------------------------------------------------------------------------
echo "DH4096 Deterministic Key Exchange"

aliceCalls = 0
bobCalls = 0

var alice4096: DH4096Ctx
alice4096.dh4096Init(aliceRng)

var bob4096: DH4096Ctx
bob4096.dh4096Init(bobRng)

echo "Alice Private Key : ", binToHex(alice4096.privateKey.data)
echo "Bob Private Key   : ", binToHex(bob4096.privateKey.data)

let aliceSecret4096: DH4096SharedSecret = alice4096.dh4096Derive(bob4096.publicKey)
let bobSecret4096: DH4096SharedSecret = bob4096.dh4096Derive(alice4096.publicKey)

echo "Alice Shared Secret : ", binToHex(aliceSecret4096)
echo "Bob Shared Secret   : ", binToHex(bobSecret4096)

doAssert aliceSecret4096 == bobSecret4096, "DH4096 Shared Secret : Mismatch"
echo "DH4096 Shared Secret : OK"
echo ""

echo "All DH tests passed."
