import "../../src/nim_cryptkit/block/aes"
import "../../src/nim_cryptkit/aead/ocb"
import "../../src/nim_cryptkit/utils/digits"
import "../../src/nim_cryptkit/utils/errorutils"
import "./test_helpers"

# ============================================================
# AES-OCB (RFC 7253, OCB3) test vectors
#   * Appendix A "Sample Results": the 16 (N,A,P,C) tuples with a
#     fixed key and 128-bit tags, the 96-bit tag example, and the
#     "wider variety of inputs" sweep for each named parameter set.
# ============================================================

var passed = 0

template ocbVector(C, init, encrypt, decrypt: untyped, T: static int,
                   name, keyHex, nonceHex, aadHex, ptHex, outHex: string) =
  block:
    let key = hexBytes(keyHex)
    let nonce = hexBytes(nonceHex)
    let aad = hexBytes(aadHex)
    let pt = hexBytes(ptHex)

    # The RFC prints C as ciphertext-core || tag.
    let (ct, tag) = ocbEncryptOne[C, 16, T](init, encrypt, key, nonce, aad, pt)
    var got = ct
    got.add(tag)
    doAssert sameHex(binToHex(got), outHex),
      name & " encrypt mismatch: got " & binToHex(got) & " want " & outHex

    let expected = hexBytes(outHex)
    let core = expected[0 ..< expected.len - T]
    let tagBytes = expected[expected.len - T ..< expected.len]
    let res = ocbDecryptOne[C, 16, T](init, encrypt, decrypt, key, nonce, aad, core, tagBytes)
    doAssert res.kind == Success, name & " decrypt failed"
    doAssert sameHex(binToHex(res.value), ptHex),
      name & " decrypt mismatch: got " & binToHex(res.value) & " want " & ptHex

    # A forged tag must be rejected.
    var badTag = tagBytes
    badTag[0] = badTag[0] xor 0x01
    let bad = ocbDecryptOne[C, 16, T](init, encrypt, decrypt, key, nonce, aad, core, badTag)
    doAssert bad.kind == Failure, name & " accepted a forged tag"

    inc passed

const OCBKey = "000102030405060708090A0B0C0D0E0F"

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #1", OCBKey,
  "BBAA99887766554433221100", "", "", "785407BFFFC8AD9EDCC5520AC9111EE6")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #2", OCBKey,
  "BBAA99887766554433221101", "0001020304050607", "0001020304050607",
  "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #3", OCBKey,
  "BBAA99887766554433221102", "0001020304050607", "", "81017F8203F081277152FADE694A0A00")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #4", OCBKey,
  "BBAA99887766554433221103", "", "0001020304050607", "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #5", OCBKey,
  "BBAA99887766554433221104", "000102030405060708090A0B0C0D0E0F", "000102030405060708090A0B0C0D0E0F",
  "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #6", OCBKey,
  "BBAA99887766554433221105", "000102030405060708090A0B0C0D0E0F", "", "8CF761B6902EF764462AD86498CA6B97")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #7", OCBKey,
  "BBAA99887766554433221106", "", "000102030405060708090A0B0C0D0E0F",
  "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #8", OCBKey,
  "BBAA99887766554433221107", "000102030405060708090A0B0C0D0E0F1011121314151617",
  "000102030405060708090A0B0C0D0E0F1011121314151617",
  "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #9", OCBKey,
  "BBAA99887766554433221108", "000102030405060708090A0B0C0D0E0F1011121314151617", "",
  "6DC225A071FC1B9F7C69F93B0F1E10DE")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #10", OCBKey,
  "BBAA99887766554433221109", "", "000102030405060708090A0B0C0D0E0F1011121314151617",
  "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #11", OCBKey,
  "BBAA9988776655443322110A", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
  "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #12", OCBKey,
  "BBAA9988776655443322110B", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "",
  "FE80690BEE8A485D11F32965BC9D2A32")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #13", OCBKey,
  "BBAA9988776655443322110C", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
  "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #14", OCBKey,
  "BBAA9988776655443322110D", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
  "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #15", OCBKey,
  "BBAA9988776655443322110E", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "",
  "C5CD9D1850C141E358649994EE701B68")

ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 16, "RFC 7253 #16", OCBKey,
  "BBAA9988776655443322110F", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
  "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479")

# 96-bit tag example (different key, 96-bit tags).
ocbVector(AES128Ctx, aes128Init, aes128Encrypt, aes128Decrypt, 12, "RFC 7253 96-bit tag",
  "0F0E0D0C0B0A09080706050403020100",
  "BBAA9988776655443322110D", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
  "1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1A0124B0A55BAE884ED93481529C76B6AD0C515F4D1CDD4FDAC4F02AA")

# ------------------------------------------------------------
# RFC 7253 "wider variety of inputs" sweep.
#   K = zeros(KEYLEN-8) || num2str(TAGLEN, 8)
#   for i = 0..127:
#     C ||= OCB-ENCRYPT(K, 3i+1, S, S)
#          || OCB-ENCRYPT(K, 3i+2, "", S)
#          || OCB-ENCRYPT(K, 3i+3, S, "")
#   Output = OCB-ENCRYPT(K, 385, C, "")
# ------------------------------------------------------------
proc num2str96(x: int): seq[uint8] =
  result = newSeq[uint8](12)
  var v = x
  for i in countdown(11, 0):
    result[i] = uint8(v and 0xFF)
    v = v shr 8

template ocbWideVector(C, init, encrypt: untyped, keyLenBits, tagLenBits: static int, expected: string) =
  block:
    var key = newSeq[uint8](keyLenBits div 8)
    key[^1] = uint8(tagLenBits)

    var data: seq[uint8]
    const T = tagLenBits div 8
    for i in 0 .. 127:
      let s = newSeq[uint8](i)
      let (c1, t1) = ocbEncryptOne[C, 16, T](init, encrypt, key, num2str96(3 * i + 1), s, s)
      data.add(c1); data.add(t1)
      let (c2, t2) = ocbEncryptOne[C, 16, T](init, encrypt, key, num2str96(3 * i + 2), @[], s)
      data.add(c2); data.add(t2)
      let (c3, t3) = ocbEncryptOne[C, 16, T](init, encrypt, key, num2str96(3 * i + 3), s, @[])
      data.add(c3); data.add(t3)

    let (cf, tf) = ocbEncryptOne[C, 16, T](init, encrypt, key, num2str96(385), data, @[])
    doAssert sameHex(binToHex(tf), expected),
      "OCB sweep mismatch: got " & binToHex(tf) & " want " & expected
    inc passed

ocbWideVector(AES128Ctx, aes128Init, aes128Encrypt, 128, 128, "67E944D23256C5E0B6C61FA22FDF1EA2")
ocbWideVector(AES192Ctx, aes192Init, aes192Encrypt, 192, 128, "F673F2C3E7174AAE7BAE986CA9F29E17")
ocbWideVector(AES256Ctx, aes256Init, aes256Encrypt, 256, 128, "D90EB8E9C977C88B79DD793D7FFA161C")
ocbWideVector(AES128Ctx, aes128Init, aes128Encrypt, 128, 96, "77A3D8E73589158D25D01209")
ocbWideVector(AES128Ctx, aes128Init, aes128Encrypt, 128, 64, "192C9B7BD90BA06A")

echo ""
echo "AES-OCB: ", passed, " vectors passed"
