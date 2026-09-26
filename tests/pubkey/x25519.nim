import ../../src/Cryptography/pubkey/x25519
import std/unittest

# ----------------------------------------------------------------------
# Hex Utilities
# ----------------------------------------------------------------------

proc hexNibble(c: char): uint8 =
  case c
  of '0'..'9': uint8(ord(c) - ord('0'))
  of 'a'..'f': uint8(ord(c) - ord('a') + 10)
  of 'A'..'F': uint8(ord(c) - ord('A') + 10)
  else:
    raise newException(ValueError, "invalid hex character")

proc hexToByteArray[N: static int](s: string): array[N, uint8] =
  doAssert s.len == 2 * N
  for i in 0 ..< N:
    let hi = int(hexNibble(s[2 * i]))
    let lo = int(hexNibble(s[2 * i + 1]))
    result[i] = uint8((hi shl 4) or lo)

proc bytesToHex(bytes: openArray[uint8]): string =
  const digits = "0123456789abcdef"
  result = newStringOfCap(bytes.len * 2)
  for b in bytes:
    let x = int(b)
    result.add digits[x shr 4]
    result.add digits[x and 0x0f]

# ----------------------------------------------------------------------
# RFC 7748 / draft-irtf-cfrg-curves Test Vectors
# ----------------------------------------------------------------------

type
  TestVector = object
    name: string
    privHex: string
    inputUHex: string
    peerPubHex: string
    outputHex: string
    isExchange: bool

const BasePointHex = "0900000000000000000000000000000000000000000000000000000000000000"

proc runRfc7748X25519Vectors*() =
  let basePoint = hexToByteArray[32](BasePointHex)

  let vectors = [
    TestVector(
      name: "RFC 7748 TEST 1 (Alice)",
      privHex: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      inputUHex: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
      peerPubHex: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      outputHex: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
      isExchange: true
    ),
    TestVector(
      name: "RFC 7748 TEST 2 (Bob)",
      privHex: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
      inputUHex: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      peerPubHex: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
      outputHex: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
      isExchange: true
    ),
    TestVector(
      name: "RFC Draft TEST 3 (Single Mult)",
      privHex: "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
      inputUHex: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
      peerPubHex: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
      outputHex: "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
      isExchange: false
    )
  ]

  for v in vectors:
    echo "==== ", v.name, " ===="

    let priv = hexToByteArray[32](v.privHex)
    var ctx: X25519Ctx
    ctx.privateKey.data = priv

    if v.isExchange:
      echo "PRIVATE_KEY  : ", bytesToHex(ctx.privateKey.data)

      var basePointPub: X25519PublicKey
      basePointPub.data = basePoint
      let derivedPubArr = x25519SharedSecret(ctx, basePointPub)

      echo "DERIVED_PUB  : ", bytesToHex(derivedPubArr)
      echo "EXPECTED_PUB : ", v.inputUHex
      doAssert derivedPubArr == hexToByteArray[32](v.inputUHex), "derived public key mismatch"

      let peerPubArr = hexToByteArray[32](v.peerPubHex)
      var peerPub: X25519PublicKey
      peerPub.data = peerPubArr

      let sharedArr = x25519SharedSecret(ctx, peerPub)

      echo "PEER_PUB     : ", v.peerPubHex
      echo "SHARED_SECRET: ", bytesToHex(sharedArr)
      echo "EXPECTED_SEC : ", v.outputHex

      doAssert sharedArr == hexToByteArray[32](v.outputHex), "shared secret mismatch"
    else:
      echo "INPUT_SCALAR : ", bytesToHex(ctx.privateKey.data)

      let inputUArr = hexToByteArray[32](v.inputUHex)
      var inputU: X25519PublicKey
      inputU.data = inputUArr

      let outputUArr = x25519SharedSecret(ctx, inputU)

      echo "INPUT_U      : ", v.inputUHex
      echo "OUTPUT_U     : ", bytesToHex(outputUArr)
      echo "EXPECTED_OUT : ", v.outputHex

      doAssert outputUArr == hexToByteArray[32](v.outputHex), "single mult mismatch"

    echo "OK"
    echo ""

when isMainModule:
  runRfc7748X25519Vectors()
