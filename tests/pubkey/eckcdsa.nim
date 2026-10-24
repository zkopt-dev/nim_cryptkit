import ../../src/Cryptography/pubkey/[eckcdsa, fixedint, ec, common]
import ../../src/Cryptography/utils/envconst
import std/strutils

# -----------------------------------------------------------------------------
# Hex Helpers
# -----------------------------------------------------------------------------
proc normalizeHex(s: string): string =
  result = s.replace("0x", "").replace("0X", "")
            .replace(" ", "").replace("\t", "")
            .replace("\r", "").replace("\n", "")
            .replace(":", "").toLowerAscii()

proc fromHexArray[N: static int](hex: string): array[N, uint8] =
  let h: string = normalizeHex(hex)
  if h.len != N * 2:
    raise newException(ValueError,
      "hex length mismatch: expected " & $(N * 2) & ", got " & $h.len)
  for i in 0 ..< N:
    result[i] = uint8(parseHexInt(h[i * 2 .. i * 2 + 1]))

proc fromHexSeq(hex: string): seq[uint8] =
  let h: string = normalizeHex(hex)
  if h.len == 0: return @[]
  if h.len mod 2 != 0:
    raise newException(ValueError, "odd-length hex string")
  result = newSeq[uint8](h.len div 2)
  for i in 0 ..< result.len:
    result[i] = uint8(parseHexInt(h[i * 2 .. i * 2 + 1]))

proc toHexLower(x: openArray[uint8]): string =
  result = ""
  for b in x: result.add b.toHex(2).toLowerAscii()

# -----------------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------------

echo "EC-KCDSA Fixed Vector Test"

let privHex: string = "0000000000000000000000000000000000000000000000000000000000000001"
let msgHex: string  = "31323334353637383930"
let nonceHex: string = "0000000000000000000000000000000000000000000000000000000000000002"

var ctx: ECKCDSACtx

let privBytes: array[32, uint8] = fromHexArray[32](privHex)
ctx.privateKey.data = privBytes
ctx.publicKeyFromPrivate()
echo "Private Key : ", toHexLower(privBytes)
echo "Public Key  : ", toHexLower(ctx.publicKey.data)

let msg: seq[uint8] = fromHexSeq(msgHex)
echo "Message     : ", toHexLower(msg)

let nonceBytes: array[32, uint8] = fromHexArray[32](nonceHex)
let nonce: BigUint[32] = fromBytesBE[32](nonceBytes)
echo "Nonce (k)   : ", toHexLower(nonceBytes)

let sig: ECKCDSASignature = ctx.signCWithNonce(msg, nonce)
echo "Signature   : ", toHexLower(sig)

doAssert ctx.eckcdsaVerify(msg, sig), "EC-KCDSA Verify : Failed"
echo "EC-KCDSA Verify : OK"
echo ""

# -----------------------------------------------------------------------------
# Determinism check: same nonce → same signature
# -----------------------------------------------------------------------------
echo "EC-KCDSA Determinism Check"
let sig2: ECKCDSASignature = ctx.signCWithNonce(msg, nonce)
doAssert sig == sig2, "EC-KCDSA Determinism : Failed"
echo "EC-KCDSA Determinism : OK"
echo ""

# -----------------------------------------------------------------------------
# Random nonce sign + verify
# -----------------------------------------------------------------------------
echo "EC-KCDSA Random Nonce Sign + Verify"
ctx.rng = systemRng
let sigRandom: ECKCDSASignature = ctx.eckcdsaSign(msg)
echo "Signature   : ", toHexLower(sigRandom)
doAssert ctx.eckcdsaVerify(msg, sigRandom), "EC-KCDSA Random Verify : Failed"
echo "EC-KCDSA Random Verify : OK"
echo ""

echo "All EC-KCDSA tests passed."
