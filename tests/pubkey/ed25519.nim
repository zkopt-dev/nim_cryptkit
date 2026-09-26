import ../../src/Cryptography/pubkey/ed25519
import std/unittest


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

proc hexToByteSeq(s: string): seq[uint8] =
  doAssert s.len mod 2 == 0
  result = newSeq[uint8](s.len div 2)
  for i in 0 ..< result.len:
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
# RFC 8032 Ed25519 test vectors
# https://www.rfc-editor.org/rfc/rfc8032#section-7.1
# ----------------------------------------------------------------------

proc runRfc8032Ed25519Vectors*() =
  let vectors = [
    (
      name: "RFC 8032 TEST 1",
      privHex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      pubHex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      msgHex: "",
      sigHex: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ),
    (
      name: "RFC 8032 TEST 2",
      privHex: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      pubHex: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      msgHex: "72",
      sigHex: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ),
    (
      name: "RFC 8032 TEST 3",
      privHex: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      pubHex: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      msgHex: "af82",
      sigHex: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    )
  ]

  for v in vectors:
    echo "==== ", v.name, " ===="

    let priv = hexToByteArray[32](v.privHex)
    let expectedPub = hexToByteArray[32](v.pubHex)
    let expectedSig = hexToByteArray[64](v.sigHex)
    let msg = hexToByteSeq(v.msgHex)

    var ctx: Ed25519Ctx

    ctx.privateKey.data = priv

    ctx.publicKeyFromPrivate()
    let derivedPub = ctx.publicKey.data

    ctx.publicKey.data = expectedPub

    let sig = signC(ctx, msg)

    echo "PRIVATE_KEY : ", bytesToHex(ctx.privateKey.data)
    echo "DERIVED_PUB : ", bytesToHex(derivedPub)
    echo "MANUAL_PUB  : ", bytesToHex(ctx.publicKey.data)
    echo "EXPECTED_PUB: ", v.pubHex

    if v.msgHex.len == 0:
      echo "MESSAGE     : (empty)"
    else:
      echo "MESSAGE     : ", v.msgHex

    echo "SIGNATURE   : ", bytesToHex(sig)
    echo "EXPECTED_SIG: ", v.sigHex

    doAssert derivedPub == expectedPub, "derived public key mismatch"
    doAssert sig == expectedSig, "signature mismatch"

    echo "OK"
    echo ""

when isMainModule:
  runRfc8032Ed25519Vectors()
