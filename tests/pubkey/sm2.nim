import ../../src/Cryptography/pubkey/[sm2, fixedint, ec]
import ../../src/Cryptography/utils/digits
import std/unittest

func nibble(c: char): uint8 =
  if c <= '9': uint8(ord(c) - ord('0'))
  elif c <= 'F': uint8(ord(c) - ord('A') + 10)
  else: uint8(ord(c) - ord('a') + 10)

proc fillHex(output: var openArray[uint8], text: string) =
  for i in 0 ..< output.len:
    output[i] = (nibble(text[2 * i]) shl 4) or nibble(text[2 * i + 1])

# -----------------------------------------------------------------------------
# Deterministic RNG — GM/T 0003.5 Annex A vector
# -----------------------------------------------------------------------------
var vectorCalls = 0
proc vectorRng(output: var openArray[uint8]) {.gcsafe, raises: [].} =
  if vectorCalls == 0:
    output.fillHex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8")
  else:
    output.fillHex("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21")
  inc vectorCalls

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
suite "Pure Nim SM2":

  test "GM/T 0003.5 Annex A — deterministic key generation":
    vectorCalls = 0
    var ctx: SM2Ctx
    ctx.sm2Init(vectorRng)

    echo ""
    echo "  [Private Key] ", binToHex(ctx.privateKey.data)
    echo "  [Public Key ] ", binToHex(ctx.publicKey.data)
    echo "  Key Generation: OK"
    echo ""

    doAssert ctx.privateKey.sm2ValidatePrivateKey(), "private key validation failed"
    doAssert ctx.publicKey.sm2ValidatePublicKey(), "public key validation failed"

  test "GM/T 0003.5 Annex A — deterministic signature":
    vectorCalls = 0
    var ctx: SM2Ctx
    ctx.keyInitC(vectorRng)

    let message: string = "message digest"
    let msgBytes: seq[uint8] = charToBin(message)
    let idBytes: seq[uint8] = charToBin(DefaultIdentity)

    let signature: SM2Signature = ctx.sm2Sign(msgBytes, idBytes)

    var expected: SM2Signature
    expected.fillHex(
      "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3" &
      "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA")

    echo "  [Message    ] ", binToHex(msgBytes)
    echo "  [Identity   ] ", binToHex(idBytes)
    echo "  [Signature  ] ", binToHex(signature)
    echo "  [Expected   ] ", binToHex(expected)

    doAssert signature == expected, "SM2 signature mismatch against official vector"
    echo "  Signature: OK"
    echo ""

  test "GM/T 0003.5 Annex A — verification":
    vectorCalls = 0
    var ctx: SM2Ctx
    ctx.sm2Init(vectorRng)

    let message: string = "message digest"
    let msgBytes: seq[uint8] = charToBin(message)
    let idBytes: seq[uint8] = charToBin(DefaultIdentity)

    var signature: SM2Signature
    signature.fillHex(
      "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3" &
      "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA")

    let valid: bool = ctx.sm2Verify(msgBytes, signature, idBytes)

    echo "  [Message    ] ", binToHex(msgBytes)
    echo "  [Signature  ] ", binToHex(signature)
    echo "  [Verify     ] ", valid

    doAssert valid, "SM2 verification failed for official vector"
    echo "  Verification: OK"
    echo ""

  test "SM2 — tampered signature must fail":
    vectorCalls = 0
    var ctx: SM2Ctx
    ctx.sm2Init(vectorRng)

    let message: string = "message digest"
    let msgBytes: seq[uint8] = charToBin(message)
    let idBytes: seq[uint8] = charToBin(DefaultIdentity)

    var signature: SM2Signature
    signature.fillHex(
      "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3" &
      "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA")

    signature[0] = signature[0] xor 0xFF'u8

    let valid: bool = ctx.sm2Verify(msgBytes, signature, idBytes)

    echo "  [Tampered   ] ", binToHex(signature)
    echo "  [Verify     ] ", valid

    doAssert not valid, "tampered signature must not pass verification"
    echo "  Tamper Detection: OK"
    echo ""

  test "SM2 — tampered message must fail":
    vectorCalls = 0
    var ctx: SM2Ctx
    ctx.sm2Init(vectorRng)

    let idBytes: seq[uint8] = charToBin(DefaultIdentity)

    var signature: SM2Signature
    signature.fillHex(
      "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3" &
      "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA")

    let tamperedMsg: string = "message dig3st"
    let tamperedBytes: seq[uint8] = charToBin(tamperedMsg)

    let valid: bool = ctx.sm2Verify(tamperedBytes, signature, idBytes)

    echo "  [Tampered Msg] ", binToHex(tamperedBytes)
    echo "  [Verify      ] ", valid

    doAssert not valid, "tampered message must not pass verification"
    echo "  Tamper Detection: OK"
    echo ""
