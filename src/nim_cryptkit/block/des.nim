import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import std/[monotimes, times]
import std/bitops
import strutils

const
  Parity: array[256, int] = [
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254
  ]

  WeakKeys: array[16, array[8, uint8]] = [
    # weak keys
    [0x01'u8, 0x01'u8, 0x01'u8, 0x01'u8, 0x01'u8, 0x01'u8, 0x01'u8, 0x01'u8],
    [0xFE'u8, 0xFE'u8, 0xFE'u8, 0xFE'u8, 0xFE'u8, 0xFE'u8, 0xFE'u8, 0xFE'u8],
    [0x1F'u8, 0x1F'u8, 0x1F'u8, 0x1F'u8, 0x0E'u8, 0x0E'u8, 0x0E'u8, 0x0E'u8],
    [0xE0'u8, 0xE0'u8, 0xE0'u8, 0xE0'u8, 0xF1'u8, 0xF1'u8, 0xF1'u8, 0xF1'u8],
    # semi-weak keys
    [0x01'u8, 0xFE'u8, 0x01'u8, 0xFE'u8, 0x01'u8, 0xFE'u8, 0x01'u8, 0xFE'u8],
    [0xFE'u8, 0x01'u8, 0xFE'u8, 0x01'u8, 0xFE'u8, 0x01'u8, 0xFE'u8, 0x01'u8],
    [0x1F'u8, 0xE0'u8, 0x1F'u8, 0xE0'u8, 0x0E'u8, 0xF1'u8, 0x0E'u8, 0xF1'u8],
    [0xE0'u8, 0x1F'u8, 0xE0'u8, 0x1F'u8, 0xF1'u8, 0x0E'u8, 0xF1'u8, 0x0E'u8],
    [0x01'u8, 0xE0'u8, 0x01'u8, 0xE0'u8, 0x01'u8, 0xF1'u8, 0x01'u8, 0xF1'u8],
    [0xE0'u8, 0x01'u8, 0xE0'u8, 0x01'u8, 0xF1'u8, 0x01'u8, 0xF1'u8, 0x01'u8],
    [0x1F'u8, 0xFE'u8, 0x1F'u8, 0xFE'u8, 0x0E'u8, 0xFE'u8, 0x0E'u8, 0xFE'u8],
    [0xFE'u8, 0x1F'u8, 0xFE'u8, 0x1F'u8, 0xFE'u8, 0x0E'u8, 0xFE'u8, 0x0E'u8],
    [0x01'u8, 0x1F'u8, 0x01'u8, 0x1F'u8, 0x01'u8, 0x0E'u8, 0x01'u8, 0x0E'u8],
    [0x1F'u8, 0x01'u8, 0x1F'u8, 0x01'u8, 0x0E'u8, 0x01'u8, 0x0E'u8, 0x01'u8],
    [0xE0'u8, 0xFE'u8, 0xE0'u8, 0xFE'u8, 0xF1'u8, 0xFE'u8, 0xF1'u8, 0xFE'u8],
    [0xFE'u8, 0xE0'u8, 0xFE'u8, 0xE0'u8, 0xFE'u8, 0xF1'u8, 0xFE'u8, 0xF1'u8]
  ]
  KeyBox*: array[8, array[64, uint32]] = [
    [
      0x00000000'u32, 0x00000010'u32, 0x20000000'u32, 0x20000010'u32, 0x00010000'u32, 0x00010010'u32, 0x20010000'u32, 0x20010010'u32,
      0x00000800'u32, 0x00000810'u32, 0x20000800'u32, 0x20000810'u32, 0x00010800'u32, 0x00010810'u32, 0x20010800'u32, 0x20010810'u32,
      0x00000020'u32, 0x00000030'u32, 0x20000020'u32, 0x20000030'u32, 0x00010020'u32, 0x00010030'u32, 0x20010020'u32, 0x20010030'u32,
      0x00000820'u32, 0x00000830'u32, 0x20000820'u32, 0x20000830'u32, 0x00010820'u32, 0x00010830'u32, 0x20010820'u32, 0x20010830'u32,
      0x00080000'u32, 0x00080010'u32, 0x20080000'u32, 0x20080010'u32, 0x00090000'u32, 0x00090010'u32, 0x20090000'u32, 0x20090010'u32,
      0x00080800'u32, 0x00080810'u32, 0x20080800'u32, 0x20080810'u32, 0x00090800'u32, 0x00090810'u32, 0x20090800'u32, 0x20090810'u32,
      0x00080020'u32, 0x00080030'u32, 0x20080020'u32, 0x20080030'u32, 0x00090020'u32, 0x00090030'u32, 0x20090020'u32, 0x20090030'u32,
      0x00080820'u32, 0x00080830'u32, 0x20080820'u32, 0x20080830'u32, 0x00090820'u32, 0x00090830'u32, 0x20090820'u32, 0x20090830'u32
    ],
    [
      0x00000000'u32, 0x02000000'u32, 0x00002000'u32, 0x02002000'u32, 0x00200000'u32, 0x02200000'u32, 0x00202000'u32, 0x02202000'u32,
      0x00000004'u32, 0x02000004'u32, 0x00002004'u32, 0x02002004'u32, 0x00200004'u32, 0x02200004'u32, 0x00202004'u32, 0x02202004'u32,
      0x00000400'u32, 0x02000400'u32, 0x00002400'u32, 0x02002400'u32, 0x00200400'u32, 0x02200400'u32, 0x00202400'u32, 0x02202400'u32,
      0x00000404'u32, 0x02000404'u32, 0x00002404'u32, 0x02002404'u32, 0x00200404'u32, 0x02200404'u32, 0x00202404'u32, 0x02202404'u32,
      0x10000000'u32, 0x12000000'u32, 0x10002000'u32, 0x12002000'u32, 0x10200000'u32, 0x12200000'u32, 0x10202000'u32, 0x12202000'u32,
      0x10000004'u32, 0x12000004'u32, 0x10002004'u32, 0x12002004'u32, 0x10200004'u32, 0x12200004'u32, 0x10202004'u32, 0x12202004'u32,
      0x10000400'u32, 0x12000400'u32, 0x10002400'u32, 0x12002400'u32, 0x10200400'u32, 0x12200400'u32, 0x10202400'u32, 0x12202400'u32,
      0x10000404'u32, 0x12000404'u32, 0x10002404'u32, 0x12002404'u32, 0x10200404'u32, 0x12200404'u32, 0x10202404'u32, 0x12202404'u32
    ],
    [
      0x00000000'u32, 0x00000001'u32, 0x00040000'u32, 0x00040001'u32, 0x01000000'u32, 0x01000001'u32, 0x01040000'u32, 0x01040001'u32,
      0x00000002'u32, 0x00000003'u32, 0x00040002'u32, 0x00040003'u32, 0x01000002'u32, 0x01000003'u32, 0x01040002'u32, 0x01040003'u32,
      0x00000200'u32, 0x00000201'u32, 0x00040200'u32, 0x00040201'u32, 0x01000200'u32, 0x01000201'u32, 0x01040200'u32, 0x01040201'u32,
      0x00000202'u32, 0x00000203'u32, 0x00040202'u32, 0x00040203'u32, 0x01000202'u32, 0x01000203'u32, 0x01040202'u32, 0x01040203'u32,
      0x08000000'u32, 0x08000001'u32, 0x08040000'u32, 0x08040001'u32, 0x09000000'u32, 0x09000001'u32, 0x09040000'u32, 0x09040001'u32,
      0x08000002'u32, 0x08000003'u32, 0x08040002'u32, 0x08040003'u32, 0x09000002'u32, 0x09000003'u32, 0x09040002'u32, 0x09040003'u32,
      0x08000200'u32, 0x08000201'u32, 0x08040200'u32, 0x08040201'u32, 0x09000200'u32, 0x09000201'u32, 0x09040200'u32, 0x09040201'u32,
      0x08000202'u32, 0x08000203'u32, 0x08040202'u32, 0x08040203'u32, 0x09000202'u32, 0x09000203'u32, 0x09040202'u32, 0x09040203'u32
    ],
    [
      0x00000000'u32, 0x00100000'u32, 0x00000100'u32, 0x00100100'u32, 0x00000008'u32, 0x00100008'u32, 0x00000108'u32, 0x00100108'u32,
      0x00001000'u32, 0x00101000'u32, 0x00001100'u32, 0x00101100'u32, 0x00001008'u32, 0x00101008'u32, 0x00001108'u32, 0x00101108'u32,
      0x04000000'u32, 0x04100000'u32, 0x04000100'u32, 0x04100100'u32, 0x04000008'u32, 0x04100008'u32, 0x04000108'u32, 0x04100108'u32,
      0x04001000'u32, 0x04101000'u32, 0x04001100'u32, 0x04101100'u32, 0x04001008'u32, 0x04101008'u32, 0x04001108'u32, 0x04101108'u32,
      0x00020000'u32, 0x00120000'u32, 0x00020100'u32, 0x00120100'u32, 0x00020008'u32, 0x00120008'u32, 0x00020108'u32, 0x00120108'u32,
      0x00021000'u32, 0x00121000'u32, 0x00021100'u32, 0x00121100'u32, 0x00021008'u32, 0x00121008'u32, 0x00021108'u32, 0x00121108'u32,
      0x04020000'u32, 0x04120000'u32, 0x04020100'u32, 0x04120100'u32, 0x04020008'u32, 0x04120008'u32, 0x04020108'u32, 0x04120108'u32,
      0x04021000'u32, 0x04121000'u32, 0x04021100'u32, 0x04121100'u32, 0x04021008'u32, 0x04121008'u32, 0x04021108'u32, 0x04121108'u32
    ],
    [
      0x00000000'u32, 0x10000000'u32, 0x00010000'u32, 0x10010000'u32, 0x00000004'u32, 0x10000004'u32, 0x00010004'u32, 0x10010004'u32,
      0x20000000'u32, 0x30000000'u32, 0x20010000'u32, 0x30010000'u32, 0x20000004'u32, 0x30000004'u32, 0x20010004'u32, 0x30010004'u32,
      0x00100000'u32, 0x10100000'u32, 0x00110000'u32, 0x10110000'u32, 0x00100004'u32, 0x10100004'u32, 0x00110004'u32, 0x10110004'u32,
      0x20100000'u32, 0x30100000'u32, 0x20110000'u32, 0x30110000'u32, 0x20100004'u32, 0x30100004'u32, 0x20110004'u32, 0x30110004'u32,
      0x00001000'u32, 0x10001000'u32, 0x00011000'u32, 0x10011000'u32, 0x00001004'u32, 0x10001004'u32, 0x00011004'u32, 0x10011004'u32,
      0x20001000'u32, 0x30001000'u32, 0x20011000'u32, 0x30011000'u32, 0x20001004'u32, 0x30001004'u32, 0x20011004'u32, 0x30011004'u32,
      0x00101000'u32, 0x10101000'u32, 0x00111000'u32, 0x10111000'u32, 0x00101004'u32, 0x10101004'u32, 0x00111004'u32, 0x10111004'u32,
      0x20101000'u32, 0x30101000'u32, 0x20111000'u32, 0x30111000'u32, 0x20101004'u32, 0x30101004'u32, 0x20111004'u32, 0x30111004'u32
    ],
    [
      0x00000000'u32, 0x08000000'u32, 0x00000008'u32, 0x08000008'u32, 0x00000400'u32, 0x08000400'u32, 0x00000408'u32, 0x08000408'u32,
      0x00020000'u32, 0x08020000'u32, 0x00020008'u32, 0x08020008'u32, 0x00020400'u32, 0x08020400'u32, 0x00020408'u32, 0x08020408'u32,
      0x00000001'u32, 0x08000001'u32, 0x00000009'u32, 0x08000009'u32, 0x00000401'u32, 0x08000401'u32, 0x00000409'u32, 0x08000409'u32,
      0x00020001'u32, 0x08020001'u32, 0x00020009'u32, 0x08020009'u32, 0x00020401'u32, 0x08020401'u32, 0x00020409'u32, 0x08020409'u32,
      0x02000000'u32, 0x0A000000'u32, 0x02000008'u32, 0x0A000008'u32, 0x02000400'u32, 0x0A000400'u32, 0x02000408'u32, 0x0A000408'u32,
      0x02020000'u32, 0x0A020000'u32, 0x02020008'u32, 0x0A020008'u32, 0x02020400'u32, 0x0A020400'u32, 0x02020408'u32, 0x0A020408'u32,
      0x02000001'u32, 0x0A000001'u32, 0x02000009'u32, 0x0A000009'u32, 0x02000401'u32, 0x0A000401'u32, 0x02000409'u32, 0x0A000409'u32,
      0x02020001'u32, 0x0A020001'u32, 0x02020009'u32, 0x0A020009'u32, 0x02020401'u32, 0x0A020401'u32, 0x02020409'u32, 0x0A020409'u32
    ],
    [
      0x00000000'u32, 0x00000100'u32, 0x00080000'u32, 0x00080100'u32, 0x01000000'u32, 0x01000100'u32, 0x01080000'u32, 0x01080100'u32,
      0x00000010'u32, 0x00000110'u32, 0x00080010'u32, 0x00080110'u32, 0x01000010'u32, 0x01000110'u32, 0x01080010'u32, 0x01080110'u32,
      0x00200000'u32, 0x00200100'u32, 0x00280000'u32, 0x00280100'u32, 0x01200000'u32, 0x01200100'u32, 0x01280000'u32, 0x01280100'u32,
      0x00200010'u32, 0x00200110'u32, 0x00280010'u32, 0x00280110'u32, 0x01200010'u32, 0x01200110'u32, 0x01280010'u32, 0x01280110'u32,
      0x00000200'u32, 0x00000300'u32, 0x00080200'u32, 0x00080300'u32, 0x01000200'u32, 0x01000300'u32, 0x01080200'u32, 0x01080300'u32,
      0x00000210'u32, 0x00000310'u32, 0x00080210'u32, 0x00080310'u32, 0x01000210'u32, 0x01000310'u32, 0x01080210'u32, 0x01080310'u32,
      0x00200200'u32, 0x00200300'u32, 0x00280200'u32, 0x00280300'u32, 0x01200200'u32, 0x01200300'u32, 0x01280200'u32, 0x01280300'u32,
      0x00200210'u32, 0x00200310'u32, 0x00280210'u32, 0x00280310'u32, 0x01200210'u32, 0x01200310'u32, 0x01280210'u32, 0x01280310'u32
    ],
    [
      0x00000000'u32, 0x04000000'u32, 0x00040000'u32, 0x04040000'u32, 0x00000002'u32, 0x04000002'u32, 0x00040002'u32, 0x04040002'u32,
      0x00002000'u32, 0x04002000'u32, 0x00042000'u32, 0x04042000'u32, 0x00002002'u32, 0x04002002'u32, 0x00042002'u32, 0x04042002'u32,
      0x00000020'u32, 0x04000020'u32, 0x00040020'u32, 0x04040020'u32, 0x00000022'u32, 0x04000022'u32, 0x00040022'u32, 0x04040022'u32,
      0x00002020'u32, 0x04002020'u32, 0x00042020'u32, 0x04042020'u32, 0x00002022'u32, 0x04002022'u32, 0x00042022'u32, 0x04042022'u32,
      0x00000800'u32, 0x04000800'u32, 0x00040800'u32, 0x04040800'u32, 0x00000802'u32, 0x04000802'u32, 0x00040802'u32, 0x04040802'u32,
      0x00002800'u32, 0x04002800'u32, 0x00042800'u32, 0x04042800'u32, 0x00002802'u32, 0x04002802'u32, 0x00042802'u32, 0x04042802'u32,
      0x00000820'u32, 0x04000820'u32, 0x00040820'u32, 0x04040820'u32, 0x00000822'u32, 0x04000822'u32, 0x00040822'u32, 0x04040822'u32,
      0x00002820'u32, 0x04002820'u32, 0x00042820'u32, 0x04042820'u32, 0x00002822'u32, 0x04002822'u32, 0x00042822'u32, 0x04042822'u32
    ]
  ]
  SP: array[8, array[64, uint32]] = [
    [
      0x02080800'u32, 0x00080000'u32, 0x02000002'u32, 0x02080802'u32, 0x02000000'u32, 0x00080802'u32, 0x00080002'u32, 0x02000002'u32,
      0x00080802'u32, 0x02080800'u32, 0x02080000'u32, 0x00000802'u32, 0x02000802'u32, 0x02000000'u32, 0x00000000'u32, 0x00080002'u32,
      0x00080000'u32, 0x00000002'u32, 0x02000800'u32, 0x00080800'u32, 0x02080802'u32, 0x02080000'u32, 0x00000802'u32, 0x02000800'u32,
      0x00000002'u32, 0x00000800'u32, 0x00080800'u32, 0x02080002'u32, 0x00000800'u32, 0x02000802'u32, 0x02080002'u32, 0x00000000'u32,
      0x00000000'u32, 0x02080802'u32, 0x02000800'u32, 0x00080002'u32, 0x02080800'u32, 0x00080000'u32, 0x00000802'u32, 0x02000800'u32,
      0x02080002'u32, 0x00000800'u32, 0x00080800'u32, 0x02000002'u32, 0x00080802'u32, 0x00000002'u32, 0x02000002'u32, 0x02080000'u32,
      0x02080802'u32, 0x00080800'u32, 0x02080000'u32, 0x02000802'u32, 0x02000000'u32, 0x00000802'u32, 0x00080002'u32, 0x00000000'u32,
      0x00080000'u32, 0x02000000'u32, 0x02000802'u32, 0x02080800'u32, 0x00000002'u32, 0x02080002'u32, 0x00000800'u32, 0x00080802'u32
    ],
    [
      0x40108010'u32, 0x00000000'u32, 0x00108000'u32, 0x40100000'u32, 0x40000010'u32, 0x00008010'u32, 0x40008000'u32, 0x00108000'u32,
      0x00008000'u32, 0x40100010'u32, 0x00000010'u32, 0x40008000'u32, 0x00100010'u32, 0x40108000'u32, 0x40100000'u32, 0x00000010'u32,
      0x00100000'u32, 0x40008010'u32, 0x40100010'u32, 0x00008000'u32, 0x00108010'u32, 0x40000000'u32, 0x00000000'u32, 0x00100010'u32,
      0x40008010'u32, 0x00108010'u32, 0x40108000'u32, 0x40000010'u32, 0x40000000'u32, 0x00100000'u32, 0x00008010'u32, 0x40108010'u32,
      0x00100010'u32, 0x40108000'u32, 0x40008000'u32, 0x00108010'u32, 0x40108010'u32, 0x00100010'u32, 0x40000010'u32, 0x00000000'u32,
      0x40000000'u32, 0x00008010'u32, 0x00100000'u32, 0x40100010'u32, 0x00008000'u32, 0x40000000'u32, 0x00108010'u32, 0x40008010'u32,
      0x40108000'u32, 0x00008000'u32, 0x00000000'u32, 0x40000010'u32, 0x00000010'u32, 0x40108010'u32, 0x00108000'u32, 0x40100000'u32,
      0x40100010'u32, 0x00100000'u32, 0x00008010'u32, 0x40008000'u32, 0x40008010'u32, 0x00000010'u32, 0x40100000'u32, 0x00108000'u32
    ],
    [
      0x04000001'u32, 0x04040100'u32, 0x00000100'u32, 0x04000101'u32, 0x00040001'u32, 0x04000000'u32, 0x04000101'u32, 0x00040100'u32,
      0x04000100'u32, 0x00040000'u32, 0x04040000'u32, 0x00000001'u32, 0x04040101'u32, 0x00000101'u32, 0x00000001'u32, 0x04040001'u32,
      0x00000000'u32, 0x00040001'u32, 0x04040100'u32, 0x00000100'u32, 0x00000101'u32, 0x04040101'u32, 0x00040000'u32, 0x04000001'u32,
      0x04040001'u32, 0x04000100'u32, 0x00040101'u32, 0x04040000'u32, 0x00040100'u32, 0x00000000'u32, 0x04000000'u32, 0x00040101'u32,
      0x04040100'u32, 0x00000100'u32, 0x00000001'u32, 0x00040000'u32, 0x00000101'u32, 0x00040001'u32, 0x04040000'u32, 0x04000101'u32,
      0x00000000'u32, 0x04040100'u32, 0x00040100'u32, 0x04040001'u32, 0x00040001'u32, 0x04000000'u32, 0x04040101'u32, 0x00000001'u32,
      0x00040101'u32, 0x04000001'u32, 0x04000000'u32, 0x04040101'u32, 0x00040000'u32, 0x04000100'u32, 0x04000101'u32, 0x00040100'u32,
      0x04000100'u32, 0x00000000'u32, 0x04040001'u32, 0x00000101'u32, 0x04000001'u32, 0x00040101'u32, 0x00000100'u32, 0x04040000'u32
    ],
    [
      0x00401008'u32, 0x10001000'u32, 0x00000008'u32, 0x10401008'u32, 0x00000000'u32, 0x10400000'u32, 0x10001008'u32, 0x00400008'u32,
      0x10401000'u32, 0x10000008'u32, 0x10000000'u32, 0x00001008'u32, 0x10000008'u32, 0x00401008'u32, 0x00400000'u32, 0x10000000'u32,
      0x10400008'u32, 0x00401000'u32, 0x00001000'u32, 0x00000008'u32, 0x00401000'u32, 0x10001008'u32, 0x10400000'u32, 0x00001000'u32,
      0x00001008'u32, 0x00000000'u32, 0x00400008'u32, 0x10401000'u32, 0x10001000'u32, 0x10400008'u32, 0x10401008'u32, 0x00400000'u32,
      0x10400008'u32, 0x00001008'u32, 0x00400000'u32, 0x10000008'u32, 0x00401000'u32, 0x10001000'u32, 0x00000008'u32, 0x10400000'u32,
      0x10001008'u32, 0x00000000'u32, 0x00001000'u32, 0x00400008'u32, 0x00000000'u32, 0x10400008'u32, 0x10401000'u32, 0x00001000'u32,
      0x10000000'u32, 0x10401008'u32, 0x00401008'u32, 0x00400000'u32, 0x10401008'u32, 0x00000008'u32, 0x10001000'u32, 0x00401008'u32,
      0x00400008'u32, 0x00401000'u32, 0x10400000'u32, 0x10001008'u32, 0x00001008'u32, 0x10000000'u32, 0x10000008'u32, 0x10401000'u32
    ],
    [
      0x08000000'u32, 0x00010000'u32, 0x00000400'u32, 0x08010420'u32, 0x08010020'u32, 0x08000400'u32, 0x00010420'u32, 0x08010000'u32,
      0x00010000'u32, 0x00000020'u32, 0x08000020'u32, 0x00010400'u32, 0x08000420'u32, 0x08010020'u32, 0x08010400'u32, 0x00000000'u32,
      0x00010400'u32, 0x08000000'u32, 0x00010020'u32, 0x00000420'u32, 0x08000400'u32, 0x00010420'u32, 0x00000000'u32, 0x08000020'u32,
      0x00000020'u32, 0x08000420'u32, 0x08010420'u32, 0x00010020'u32, 0x08010000'u32, 0x00000400'u32, 0x00000420'u32, 0x08010400'u32,
      0x08010400'u32, 0x08000420'u32, 0x00010020'u32, 0x08010000'u32, 0x00010000'u32, 0x00000020'u32, 0x08000020'u32, 0x08000400'u32,
      0x08000000'u32, 0x00010400'u32, 0x08010420'u32, 0x00000000'u32, 0x00010420'u32, 0x08000000'u32, 0x00000400'u32, 0x00010020'u32,
      0x08000420'u32, 0x00000400'u32, 0x00000000'u32, 0x08010420'u32, 0x08010020'u32, 0x08010400'u32, 0x00000420'u32, 0x00010000'u32,
      0x00010400'u32, 0x08010020'u32, 0x08000400'u32, 0x00000420'u32, 0x00000020'u32, 0x00010420'u32, 0x08010000'u32, 0x08000020'u32
    ],
    [
      0x80000040'u32, 0x00200040'u32, 0x00000000'u32, 0x80202000'u32, 0x00200040'u32, 0x00002000'u32, 0x80002040'u32, 0x00200000'u32,
      0x00002040'u32, 0x80202040'u32, 0x00202000'u32, 0x80000000'u32, 0x80002000'u32, 0x80000040'u32, 0x80200000'u32, 0x00202040'u32,
      0x00200000'u32, 0x80002040'u32, 0x80200040'u32, 0x00000000'u32, 0x00002000'u32, 0x00000040'u32, 0x80202000'u32, 0x80200040'u32,
      0x80202040'u32, 0x80200000'u32, 0x80000000'u32, 0x00002040'u32, 0x00000040'u32, 0x00202000'u32, 0x00202040'u32, 0x80002000'u32,
      0x00002040'u32, 0x80000000'u32, 0x80002000'u32, 0x00202040'u32, 0x80202000'u32, 0x00200040'u32, 0x00000000'u32, 0x80002000'u32,
      0x80000000'u32, 0x00002000'u32, 0x80200040'u32, 0x00200000'u32, 0x00200040'u32, 0x80202040'u32, 0x00202000'u32, 0x00000040'u32,
      0x80202040'u32, 0x00202000'u32, 0x00200000'u32, 0x80002040'u32, 0x80000040'u32, 0x80200000'u32, 0x00202040'u32, 0x00000000'u32,
      0x00002000'u32, 0x80000040'u32, 0x80002040'u32, 0x80202000'u32, 0x80200000'u32, 0x00002040'u32, 0x00000040'u32, 0x80200040'u32
    ],
    [
      0x00004000'u32, 0x00000200'u32, 0x01000200'u32, 0x01000004'u32, 0x01004204'u32, 0x00004004'u32, 0x00004200'u32, 0x00000000'u32,
      0x01000000'u32, 0x01000204'u32, 0x00000204'u32, 0x01004000'u32, 0x00000004'u32, 0x01004200'u32, 0x01004000'u32, 0x00000204'u32,
      0x01000204'u32, 0x00004000'u32, 0x00004004'u32, 0x01004204'u32, 0x00000000'u32, 0x01000200'u32, 0x01000004'u32, 0x00004200'u32,
      0x01004004'u32, 0x00004204'u32, 0x01004200'u32, 0x00000004'u32, 0x00004204'u32, 0x01004004'u32, 0x00000200'u32, 0x01000000'u32,
      0x00004204'u32, 0x01004000'u32, 0x01004004'u32, 0x00000204'u32, 0x00004000'u32, 0x00000200'u32, 0x01000000'u32, 0x01004004'u32,
      0x01000204'u32, 0x00004204'u32, 0x00004200'u32, 0x00000000'u32, 0x00000200'u32, 0x01000004'u32, 0x00000004'u32, 0x01000200'u32,
      0x00000000'u32, 0x01000204'u32, 0x01000200'u32, 0x00004200'u32, 0x00000204'u32, 0x00004000'u32, 0x01004204'u32, 0x01000000'u32,
      0x01004200'u32, 0x00000004'u32, 0x00004004'u32, 0x01004204'u32, 0x01000004'u32, 0x01004200'u32, 0x01004000'u32, 0x00004004'u32
    ],
    [
      0x20800080'u32, 0x20820000'u32, 0x00020080'u32, 0x00000000'u32, 0x20020000'u32, 0x00800080'u32, 0x20800000'u32, 0x20820080'u32,
      0x00000080'u32, 0x20000000'u32, 0x00820000'u32, 0x00020080'u32, 0x00820080'u32, 0x20020080'u32, 0x20000080'u32, 0x20800000'u32,
      0x00020000'u32, 0x00820080'u32, 0x00800080'u32, 0x20020000'u32, 0x20820080'u32, 0x20000080'u32, 0x00000000'u32, 0x00820000'u32,
      0x20000000'u32, 0x00800000'u32, 0x20020080'u32, 0x20800080'u32, 0x00800000'u32, 0x00020000'u32, 0x20820000'u32, 0x00000080'u32,
      0x00800000'u32, 0x00020000'u32, 0x20000080'u32, 0x20820080'u32, 0x00020080'u32, 0x20000000'u32, 0x00000000'u32, 0x00820000'u32,
      0x20800080'u32, 0x20020080'u32, 0x20020000'u32, 0x00800080'u32, 0x20820000'u32, 0x00000080'u32, 0x00800080'u32, 0x20020000'u32,
      0x20820080'u32, 0x00800000'u32, 0x20800000'u32, 0x20000080'u32, 0x00820000'u32, 0x00020080'u32, 0x20020080'u32, 0x20800000'u32,
      0x00000080'u32, 0x20820000'u32, 0x00820080'u32, 0x00000000'u32, 0x20000000'u32, 0x20800080'u32, 0x00020000'u32, 0x00820080'u32
    ]
  ]

type
  DESCtx* = object
    roundKey*: array[32, uint32]

template permOp(a, b, t: var uint32, n: static int, m: uint32): void =
  t = (((a shr n) xor b) and m)
  b = b xor t
  a = a xor (t shl n)

template hpermOp(a, t: var uint32, n: int, m: uint32): void =
  t = ((a shl (16 - n)) xor a) and m
  a = a xor t xor (t shr (16 - n))

template initPermute(l, r: var uint32): void =
  var temp: uint32
  permOp(r, l, temp, 4, 0x0F0F0F0F'u32)
  permOp(l, r, temp, 16, 0x0000FFFF'u32)
  permOp(r, l, temp, 2, 0x33333333'u32)
  permOp(l, r, temp, 8, 0x00FF00FF'u32)
  permOp(r, l, temp, 1, 0x55555555'u32)

template finalPermute(l, r: var uint32): void =
  var temp: uint32
  permOp(l, r, temp, 1,  0x55555555'u32)
  permOp(r, l, temp, 8,  0x00FF00FF'u32)
  permOp(l, r, temp, 2,  0x33333333'u32)
  permOp(r, l, temp, 16, 0x0000FFFF'u32)
  permOp(l, r, temp, 4,  0x0F0F0F0F'u32)

template dcrypt*(l, r: var uint32, s: int, roundKey: array[32, uint32]): void =
  var u: uint32 = r xor roundKey[s + 0]
  var t: uint32 = r xor roundKey[s + 1]
  t = rotateRightBits(t, 4)

  l = l xor (
    SP[0][int((u shr 2) and 0x3F'u32)] xor
    SP[2][int((u shr 10) and 0x3F'u32)] xor
    SP[4][int((u shr 18) and 0x3F'u32)] xor
    SP[6][int((u shr 26) and 0x3F'u32)] xor
    SP[1][int((t shr 2) and 0x3F'u32)] xor
    SP[3][int((t shr 10) and 0x3F'u32)] xor
    SP[5][int((t shr 18) and 0x3F'u32)] xor
    SP[7][int((t shr 26) and 0x3F'u32)]
  )

template desInitC(ctx: var DESCtx, key: slicearray[8, uint8]): void =
  var c, d, t, s, t2: uint32
  
  fromBytesLE(key.toSliceArray(0, 3), c)
  fromBytesLE(key.toSliceArray(4, 7), d)

  permOp(d, c, t, 4, 0x0f0f0f0f'u32)
  hpermOp(c, t, -2, 0xcccc0000'u32)
  hpermOp(d, t, -2, 0xcccc0000'u32)
  permOp(d, c, t, 1, 0x55555555'u32)
  permOp(c, d, t, 8, 0x00ff00ff'u32)
  permOp(d, c, t, 1, 0x55555555'u32)

  d = (((d and 0x000000FF'u32) shl 16) or
        (d and 0x0000FF00'u32) or
       ((d and 0x00FF0000'u32) shr 16) or 
       ((c and 0xF0000000'u32) shr 4))

  c = c and 0x0FFFFFFF'u32

  template round(i: static int, b: static bool): void =
    when b == true:
      c = ((c shr 2) or (c shl 26))
      d = ((d shr 2) or (d shl 26))
    else:
      c = ((c shr 1) or (c shl 27))
      d = ((d shr 1) or (d shl 27))

    c = c and 0x0FFFFFFF'u32
    d = d and 0x0FFFFFFF'u32

    s = KeyBox[0][int(c and 0x3F'u32)] or
        KeyBox[1][int(((c shr 6) and 0x03'u32) or ((c shr 7) and 0x3C'u32))] or
        KeyBox[2][int(((c shr 13) and 0x0F'u32) or ((c shr 14) and 0x30'u32))] or 
        KeyBox[3][int(((c shr 20) and 0x01'u32) or ((c shr 21) and 0x06'u32) or ((c shr 22) and 0x38'u32))]

    t = KeyBox[4][int(d and 0x3F'u32)] or 
        KeyBox[5][int(((d shr 7) and 0x03'u32) or ((d shr 8) and 0x3C'u32))] or 
        KeyBox[6][int((d shr 15) and 0x3F'u32)] or 
        KeyBox[7][int(((d shr 21) and 0x0F'u32) or ((d shr 22) and 0x30'u32))]

    t2 = ((t shl 16) or (s and 0x0000FFFF'u32)) and 0xFFFFFFFF'u32
    ctx.roundKey[i] = rotateRightBits(t2, 30) and 0xFFFFFFFF'u32
    
    t2 = ((s shr 16) or (t and 0xFFFF0000'u32))
    ctx.roundKey[i + 1] = rotateRightBits(t2, 26) and 0xFFFFFFFF'u32

  round(0, false); round(2, false); round(4, true); round(6, true)
  round(8, true); round(10, true); round(12, true); round(14, true)
  round(16, false); round(18, true); round(20, true); round(22, true)
  round(24, true); round(26, true); round(28, true); round(30, false)

template desEncryptC(ctx: DESCtx, input, output: slicearray[8, uint8]): void =
  var r, l: uint32
  fromBytesLE(input.toSliceArray(0, 3), r)
  fromBytesLE(input.toSliceArray(4, 7), l)

  initPermute(r, l)
  r = rotateRightBits(r, 29) and 0xFFFFFFFF'u32
  l = rotateRightBits(l, 29) and 0xFFFFFFFF'u32

  dcrypt(l, r, 0, ctx.roundKey);  dcrypt(r, l, 2, ctx.roundKey)
  dcrypt(l, r, 4, ctx.roundKey);  dcrypt(r, l, 6, ctx.roundKey)
  dcrypt(l, r, 8, ctx.roundKey);  dcrypt(r, l, 10, ctx.roundKey)
  dcrypt(l, r, 12, ctx.roundKey); dcrypt(r, l, 14, ctx.roundKey)
  dcrypt(l, r, 16, ctx.roundKey); dcrypt(r, l, 18, ctx.roundKey)
  dcrypt(l, r, 20, ctx.roundKey); dcrypt(r, l, 22, ctx.roundKey)
  dcrypt(l, r, 24, ctx.roundKey); dcrypt(r, l, 26, ctx.roundKey)
  dcrypt(l, r, 28, ctx.roundKey); dcrypt(r, l, 30, ctx.roundKey)

  l = rotateRightBits(l, 3) and 0xFFFFFFFF'u32
  r = rotateRightBits(r, 3) and 0xFFFFFFFF'u32

  finalPermute(r, l)

  toBytesLE(l, output.toSliceArray(0, 3))
  toBytesLE(r, output.toSliceArray(4, 7))

template desDecryptC(ctx: DESCtx, input, output: slicearray[8, uint8]): void =
  var r, l: uint32
  fromBytesLE(input.toSliceArray(0, 3), r)
  fromBytesLE(input.toSliceArray(4, 7), l)

  initPermute(r, l)
  r = rotateRightBits(r, 29) and 0xFFFFFFFF'u32
  l = rotateRightBits(l, 29) and 0xFFFFFFFF'u32

  dcrypt(l, r, 30, ctx.roundKey); dcrypt(r, l, 28, ctx.roundKey)
  dcrypt(l, r, 26, ctx.roundKey); dcrypt(r, l, 24, ctx.roundKey)
  dcrypt(l, r, 22, ctx.roundKey); dcrypt(r, l, 20, ctx.roundKey)
  dcrypt(l, r, 18, ctx.roundKey); dcrypt(r, l, 16, ctx.roundKey)
  dcrypt(l, r, 14, ctx.roundKey); dcrypt(r, l, 12, ctx.roundKey)
  dcrypt(l, r, 10, ctx.roundKey); dcrypt(r, l, 8, ctx.roundKey)
  dcrypt(l, r, 6, ctx.roundKey);  dcrypt(r, l, 4, ctx.roundKey)
  dcrypt(l, r, 2, ctx.roundKey);  dcrypt(r, l, 0, ctx.roundKey)

  l = rotateRightBits(l, 3) and 0xFFFFFFFF'u32
  r = rotateRightBits(r, 3) and 0xFFFFFFFF'u32

  finalPermute(r, l)

  toBytesLE(l, output.toSliceArray(0, 3))
  toBytesLE(r, output.toSliceArray(4, 7))

#[
const
  # key permutation constants
  KEY_PERMUTE: array[56, int] = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
  ]
  # message permutation constants
  MESSAGE_PERMUTE: array[64, int] = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
  ]
  # key shift constants
  KEY_SHIFT: array[17, int] = [
    -1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
  ]
  # subkey permutation constants
  SUBKEY_PERMUTE: array[48, int] = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
  ]
  # message expansion constants
  MESSAGE_EXPAND: array[48, int] = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
  ]
  # S round constants 1 ~ 8
  S1: array[64, int] = [
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
  ]
  S2: array[64, int] = [
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
  ]
  S3: array[64, int] = [
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
  ]
  S4: array[64, int] = [
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
  ]
  S5: array[64, int] = [
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
  ]
  S6: array[64, int] = [
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
  ]
  S7: array[64, int] = [
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
  ]
  S8: array[64, int] = [
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
  ]
  # right sub message permutation constants
  RIGHT_SUB_MESSAGE_PERMUTE: array[32, int] = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
  ]
  # final message permutation constants
  FINAL_MESSAGE_PERMUTE: array[64, int] = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
  ]

type
  # DES context
  DESCtx* = object
    encryptRoundKey*: array[128, uint8]
    decryptRoundKey*: array[128, uint8]
    leftState*: array[128, uint8]
    rightState*: array[128, uint8]



# des init core
template desInitC(ctx: var DESCtx, key: slicearray[8, uint8]): void =
  # declare left/right state, init permute
  var leftState: array[4, uint8]
  var rightState: array[4, uint8]
  var initPermute: array[8, uint8]

  # Initial key permutation
  for i in static(0 ..< 56):
    let bitIndex = KEY_PERMUTE[i] - 1
    let bitValue = (key[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
    initPermute[i div 8] = initPermute[i div 8] or (bitValue shl (7 - (i mod 8)))

  # left/right state permutation
  for i in static(0 ..< 3):
    leftState[i] = initPermute[i]
  leftState[3] = initPermute[3] and 0xF0'u8

  # right sub message permutation
  for i in static(0 ..< 3):
    rightState[i] = (initPermute[i + 3] and 0x0F'u8) shl 4
    rightState[i] = rightState[i] or ((initPermute[i + 4] and 0xF0'u8) shr 4)
  rightState[3] = (initPermute[6] and 0x0F'u8) shl 4

  # round key generation
  for round in static(1 .. 16):
    let shiftSize = KEY_SHIFT[round]
    let shiftMask = if shiftSize == 1: 0x80'u8 else: 0xC0'u8

    let left0 = shiftMask and leftState[0]
    let left1 = shiftMask and leftState[1]
    let left2 = shiftMask and leftState[2]
    let left3 = shiftMask and leftState[3]

    leftState[0] = (leftState[0] shl shiftSize) or (left1 shr (8 - shiftSize))
    leftState[1] = (leftState[1] shl shiftSize) or (left2 shr (8 - shiftSize))
    leftState[2] = (leftState[2] shl shiftSize) or (left3 shr (8 - shiftSize))
    leftState[3] = (leftState[3] shl shiftSize) or (left0 shr (4 - shiftSize))

    let right0 = shiftMask and rightState[0]
    let right1 = shiftMask and rightState[1]
    let right2 = shiftMask and rightState[2]
    let right3 = shiftMask and rightState[3]

    rightState[0] = (rightState[0] shl shiftSize) or (right1 shr (8 - shiftSize))
    rightState[1] = (rightState[1] shl shiftSize) or (right2 shr (8 - shiftSize))
    rightState[2] = (rightState[2] shl shiftSize) or (right3 shr (8 - shiftSize))
    rightState[3] = (rightState[3] shl shiftSize) or (right0 shr (4 - shiftSize))

    let roundKeyOffset = (round - 1) * 8
    for i in static(0 ..< 8): ctx.encryptRoundKey[roundKeyOffset + i] = 0
    
    for j in static(0 ..< 48):
      let subKeyShiftSize = SUBKEY_PERMUTE[j]
      var bitValue: uint8
      if subKeyShiftSize <= 28:
        let bitIndex = subKeyShiftSize - 1
        bitValue = (leftState[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
      else:
        let bitIndex = subKeyShiftSize - 29
        bitValue = (rightState[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
        
      ctx.encryptRoundKey[roundKeyOffset + (j div 8)] = ctx.encryptRoundKey[roundKeyOffset + (j div 8)] or (bitValue shl (7 - (j mod 8)))
    
  # decrypt round key generation
  copyMem(addr ctx.decryptRoundKey[0], addr ctx.encryptRoundKey[0], 128)

# des encrypt core
template desEncryptC(ctx: DESCtx, input, output: slicearray[8, uint8]): void =
  # declare chunk, init permute
  var chunk: array[8, uint8]
  copyMem(addr chunk[0], addr input[0], 8)
  var initPermute: array[8, uint8]

  # message permutation
  for i in static(0 ..< 64):
    let bitIndex = MESSAGE_PERMUTE[i] - 1
    let bitValue = (chunk[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
    initPermute[i div 8] = initPermute[i div 8] or (bitValue shl (7 - (i mod 8)))

  # left/right state permutation
  var leftState, rightState: array[4, uint8]
  for i in static(0 ..< 4):
    leftState[i] = initPermute[i]
    rightState[i] = initPermute[i + 4]

  # round/right state generation
  var leftNext, rightNext: array[4, uint8]
  var expandRight: array[6, uint8]
  var subRight: array[4, uint8]

  # round/right state generation
  for round in static(1 .. 16):
    for i in static(0 ..< 4):
      leftNext[i] = rightState[i]

    for i in static(0 ..< 6): expandRight[i] = 0
    for i in static(0 ..< 48):
      let bitIndex = MESSAGE_EXPAND[i] - 1
      let bitValue = (rightState[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
      expandRight[i div 8] = expandRight[i div 8] or (bitValue shl (7 - (i mod 8)))

    let offset = (round - 1) * 8
    for i in static(0 ..< 6):
      expandRight[i] = expandRight[i] xor ctx.encryptRoundKey[offset + i]

    for i in static(0 ..< 4): subRight[i] = 0

    # S-box lookups
    # S1
    var row = ((expandRight[0] and 0x80) shr 6) or ((expandRight[0] and 0x04) shr 2)
    var column = (expandRight[0] and 0x78) shr 3
    subRight[0] = subRight[0] or (uint8(S1[row.int * 16 + column.int]) shl 4)
    # S2
    row = (expandRight[0] and 0x02) or ((expandRight[1] and 0x10) shr 4)
    column = ((expandRight[0] and 0x01) shl 3) or ((expandRight[1] and 0xE0) shr 5)
    subRight[0] = subRight[0] or (uint8(S2[row.int * 16 + column.int]))
    # S3
    row = ((expandRight[1] and 0x08) shr 2) or ((expandRight[2] and 0x40) shr 6)
    column = ((expandRight[1] and 0x07) shl 1) or ((expandRight[2] and 0x80) shr 7)
    subRight[1] = subRight[1] or (uint8(S3[row.int * 16 + column.int]) shl 4)
    # S4
    row = ((expandRight[2] and 0x20) shr 4) or ((expandRight[2] and 0x01))
    column = (expandRight[2] and 0x1E) shr 1
    subRight[1] = subRight[1] or (uint8(S4[row.int * 16 + column.int]))
    # S5
    row = ((expandRight[3] and 0x80) shr 6) or ((expandRight[3] and 0x04) shr 2)
    column = (expandRight[3] and 0x78) shr 3
    subRight[2] = subRight[2] or (uint8(S5[row.int * 16 + column.int]) shl 4)
    # S6
    row = (expandRight[3] and 0x02) or ((expandRight[4] and 0x10) shr 4)
    column = ((expandRight[3] and 0x01) shl 3) or ((expandRight[4] and 0xE0) shr 5)
    subRight[2] = subRight[2] or (uint8(S6[row.int * 16 + column.int]))
    # S7
    row = ((expandRight[4] and 0x08) shr 2) or ((expandRight[5] and 0x40) shr 6)
    column = ((expandRight[4] and 0x07) shl 1) or ((expandRight[5] and 0x80) shr 7)
    subRight[3] = subRight[3] or (uint8(S7[row.int * 16 + column.int]) shl 4)
    # S8
    row = ((expandRight[5] and 0x20) shr 4) or (expandRight[5] and 0x01)
    column = (expandRight[5] and 0x1E) shr 1
    subRight[3] = subRight[3] or uint8(S8[row.int * 16 + column.int])

    # right state generation
    # zero right next
    zeroMem(addr rightNext[0], 4)
    for i in static(0 ..< 32):
      let bitIndex = RIGHT_SUB_MESSAGE_PERMUTE[i] - 1
      let bitValue = (subRight[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
      rightNext[i div 8] = rightNext[i div 8] or (bitValue shl (7 - (i mod 8)))

    for i in static(0 ..< 4):
      rightNext[i] = rightNext[i] xor leftState[i]

    for i in static(0 ..< 4):
      leftState[i] = leftNext[i]
      rightState[i] = rightNext[i]

  # pre-end permutation
  var preEndPermutation: array[8, uint8]
  for i in static(0 ..< 4):
    preEndPermutation[i] = rightState[i]
    preEndPermutation[4 + i] = leftState[i]

  # zero state
  zeroMem(addr output[0], 8)

  # final message permutation
  for i in static(0 ..< 64):
    let bitIndex = FINAL_MESSAGE_PERMUTE[i] - 1
    let bitValue = (preEndPermutation[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
    output[i div 8] = output[i div 8] or (bitValue shl (7 - (i mod 8)))

# des decrypt core
template desDecryptC(ctx: DESCtx, input, output: slicearray[8, uint8]): void =
  # declare and initialise chunk
  var chunk: array[8, uint8]
  copyMem(addr chunk[0], addr input[0], 8)

  # initial permutation
  var initPermute: array[8, uint8]
  for i in static(0 ..< 64):
    let bitIndex = MESSAGE_PERMUTE[i] - 1
    let bitValue = (chunk[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
    initPermute[i div 8] = initPermute[i div 8] or (bitValue shl (7 - (i mod 8)))

  # round/right state generation
  var leftState, rightState: array[4, uint8]
  for i in static(0 ..< 4):
    leftState[i] = initPermute[i]
    rightState[i] = initPermute[i + 4]

  # declare temporary variables
  var leftNext, rightNext: array[4, uint8]
  var expandRight: array[6, uint8]
  var subRight: array[4, uint8]

  # round loop
  for round in static(1 .. 16):
    for i in static(0 ..< 4):
      leftNext[i] = rightState[i]
      
    for i in static(0 ..< 6):
      expandRight[i] = 0
    for i in static(0 ..< 48):
      let bitIndex = MESSAGE_EXPAND[i] - 1
      let bitValue = (rightState[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
      expandRight[i div 8] = expandRight[i div 8] or (bitValue shl (7 - (i mod 8)))

    let offset = (16 - round) * 8
    for i in static(0 ..< 6):
      expandRight[i] = expandRight[i] xor ctx.decryptRoundKey[offset + i]

    zeroMem(addr subRight[0], 4)

    # S-box lookups
    # S1
    var row = ((expandRight[0] and 0x80) shr 6) or ((expandRight[0] and 0x04) shr 2)
    var column = (expandRight[0] and 0x78) shr 3
    subRight[0] = subRight[0] or (uint8(S1[row.int * 16 + column.int]) shl 4)
    # S2
    row = (expandRight[0] and 0x02) or ((expandRight[1] and 0x10) shr 4)
    column = ((expandRight[0] and 0x01) shl 3) or ((expandRight[1] and 0xE0) shr 5)
    subRight[0] = subRight[0] or (uint8(S2[row.int * 16 + column.int])) 
    # S3
    row = ((expandRight[1] and 0x08) shr 2) or ((expandRight[2] and 0x40) shr 6)
    column = ((expandRight[1] and 0x07) shl 1) or ((expandRight[2] and 0x80) shr 7)
    subRight[1] = subRight[1] or (uint8(S3[row.int * 16 + column.int]) shl 4)
    # S4
    row = ((expandRight[2] and 0x20) shr 4) or ((expandRight[2] and 0x01))
    column = (expandRight[2] and 0x1E) shr 1
    subRight[1] = subRight[1] or uint8(S4[row.int * 16 + column.int])
    # S5
    row = ((expandRight[3] and 0x80) shr 6) or ((expandRight[3] and 0x04) shr 2)
    column = (expandRight[3] and 0x78) shr 3
    subRight[2] = subRight[2] or (uint8(S5[row.int * 16 + column.int]) shl 4)
    # S6
    row = (expandRight[3] and 0x02) or ((expandRight[4] and 0x10) shr 4)
    column = ((expandRight[3] and 0x01) shl 3) or ((expandRight[4] and 0xE0) shr 5)
    subRight[2] = subRight[2] or (uint8(S6[row.int * 16 + column.int]))
    # S7
    row = ((expandRight[4] and 0x08) shr 2) or ((expandRight[5] and 0x40) shr 6)
    column = ((expandRight[4] and 0x07) shl 1) or ((expandRight[5] and 0x80) shr 7)
    subRight[3] = subRight[3] or (uint8(S7[row.int * 16 + column.int]) shl 4)
    # S8
    row = ((expandRight[5] and 0x20) shr 4) or (expandRight[5] and 0x01)
    column = (expandRight[5] and 0x1E) shr 1
    subRight[3] = subRight[3] or uint8(S8[row.int * 16 + column.int])

    zeroMem(addr rightNext[0], 4)
    for i in static(0 ..< 32):
      let bitIndex = RIGHT_SUB_MESSAGE_PERMUTE[i] - 1
      let bitValue = (subRight[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
      rightNext[i div 8] = rightNext[i div 8] or (bitValue shl (7 - (i mod 8)))

    for i in static(0 ..< 4):
      rightNext[i] = rightNext[i] xor leftState[i]

    for i in static(0 ..< 4):
      leftState[i] = leftNext[i]
      rightState[i] = rightNext[i]

  var preEndPermutation: array[8, uint8]
  for i in static(0 ..< 4):
    preEndPermutation[i] = rightState[i]
    preEndPermutation[4 + i] = leftState[i]

  # zero state
  zeroMem(addr output[0], 8)
  
  for i in static(0 ..< 64):
    let bitIndex = FINAL_MESSAGE_PERMUTE[i] - 1
    let bitValue = (preEndPermutation[bitIndex div 8] shr (7 - (bitIndex mod 8))) and 0x01'u8
    output[i div 8] = output[i div 8] or (bitValue shl (7 - (i mod 8)))
  ]#
# export wrappers
when defined(templateOpt):
  template desInit*(ctx: var DESCtx, key: array[8, uint8]): void =
    desInitC(ctx, key.toSliceArray(0, 7))
  template desInit*(ctx: var DESCtx, key: openArray[uint8]): void =
    desInitC(ctx, key.toSliceArray(0, 7))
  template desInit*(ctx: var DESCtx, key: slicearray[8, uint8]): void =
    desInitC(ctx, key)
  template desInit*(ctx: ptr DESCtx, key: ptr array[8, uint8]): void =
    desInitC(ctx[], key.toSliceArray(0, 7))

  template desEncrypt*(ctx: var DESCtx, input: array[8, uint8], output: var array[8, uint8]): void =
    desEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template desEncrypt*(ctx: var DESCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    desEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template desEncrypt*(ctx: var DESCtx, input, output: slicearray[8, uint8]): void =
    desEncryptC(ctx, input, output)
  template dseEncrypt*(ctx: ptr DESCtx, input, output: ptr array[8, uint8]): void =
    desEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template desDecrypt*(ctx: var DESCtx, input: array[8, uint8], output: var array[8, uint8]): void =
    desDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template desDecrypt*(ctx: var DESCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    desDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template desDecrypt*(ctx: var DESCtx, input, output: slicearray[8, uint8]): void =
    desDecryptC(ctx, input, output)
  template dseDecrypt*(ctx: ptr DESCtx, input, output: ptr array[8, uint8]): void =
    desDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))
else:
  proc desInit*(ctx: var DESCtx, key: array[8, uint8]): void =
    desInitC(ctx, key.toSliceArray(0, 7))
  proc desInit*(ctx: var DESCtx, key: openArray[uint8]): void =
    desInitC(ctx, key.toSliceArray(0, 7))
  proc desInit*(ctx: var DESCtx, key: slicearray[8, uint8]): void =
    desInitC(ctx, key)
  proc desInit*(ctx: ptr DESCtx, key: ptr array[8, uint8]): void {.exportc: "desInit".} =
    desInitC(ctx[], key.toSliceArray(0, 7))

  proc desEncrypt*(ctx: var DESCtx, input: array[8, uint8], output: var array[8, uint8]): void =
    desEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc desEncrypt*(ctx: var DESCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    desEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc desEncrypt*(ctx: var DESCtx, input, output: slicearray[8, uint8]): void =
    desEncryptC(ctx, input, output)
  proc dseEncrypt*(ctx: ptr DESCtx, input, output: ptr array[8, uint8]): void {.exportc: "desEncrypt".} =
    desEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc desDecrypt*(ctx: var DESCtx, input: array[8, uint8], output: var array[8, uint8]): void =
    desDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc desDecrypt*(ctx: var DESCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    desDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc desDecrypt*(ctx: var DESCtx, input, output: slicearray[8, uint8]): void =
    desDecryptC(ctx, input, output)
  proc dseDecrypt*(ctx: ptr DESCtx, input, output: ptr array[8, uint8]): void {.exportc: "desDecrypt".} =
    desDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))
