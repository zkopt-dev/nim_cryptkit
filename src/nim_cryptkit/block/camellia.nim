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
  SBox1: array[256, uint32] = [
    0x70707000'u32, 0x82828200'u32, 0x2c2c2c00'u32, 0xececec00'u32, 0xb3b3b300'u32, 0x27272700'u32, 0xc0c0c000'u32, 0xe5e5e500'u32,
    0xe4e4e400'u32, 0x85858500'u32, 0x57575700'u32, 0x35353500'u32, 0xeaeaea00'u32, 0x0c0c0c00'u32, 0xaeaeae00'u32, 0x41414100'u32,
    0x23232300'u32, 0xefefef00'u32, 0x6b6b6b00'u32, 0x93939300'u32, 0x45454500'u32, 0x19191900'u32, 0xa5a5a500'u32, 0x21212100'u32,
    0xededed00'u32, 0x0e0e0e00'u32, 0x4f4f4f00'u32, 0x4e4e4e00'u32, 0x1d1d1d00'u32, 0x65656500'u32, 0x92929200'u32, 0xbdbdbd00'u32,
    0x86868600'u32, 0xb8b8b800'u32, 0xafafaf00'u32, 0x8f8f8f00'u32, 0x7c7c7c00'u32, 0xebebeb00'u32, 0x1f1f1f00'u32, 0xcecece00'u32,
    0x3e3e3e00'u32, 0x30303000'u32, 0xdcdcdc00'u32, 0x5f5f5f00'u32, 0x5e5e5e00'u32, 0xc5c5c500'u32, 0x0b0b0b00'u32, 0x1a1a1a00'u32,
    0xa6a6a600'u32, 0xe1e1e100'u32, 0x39393900'u32, 0xcacaca00'u32, 0xd5d5d500'u32, 0x47474700'u32, 0x5d5d5d00'u32, 0x3d3d3d00'u32,
    0xd9d9d900'u32, 0x01010100'u32, 0x5a5a5a00'u32, 0xd6d6d600'u32, 0x51515100'u32, 0x56565600'u32, 0x6c6c6c00'u32, 0x4d4d4d00'u32,
    0x8b8b8b00'u32, 0x0d0d0d00'u32, 0x9a9a9a00'u32, 0x66666600'u32, 0xfbfbfb00'u32, 0xcccccc00'u32, 0xb0b0b000'u32, 0x2d2d2d00'u32,
    0x74747400'u32, 0x12121200'u32, 0x2b2b2b00'u32, 0x20202000'u32, 0xf0f0f000'u32, 0xb1b1b100'u32, 0x84848400'u32, 0x99999900'u32,
    0xdfdfdf00'u32, 0x4c4c4c00'u32, 0xcbcbcb00'u32, 0xc2c2c200'u32, 0x34343400'u32, 0x7e7e7e00'u32, 0x76767600'u32, 0x05050500'u32,
    0x6d6d6d00'u32, 0xb7b7b700'u32, 0xa9a9a900'u32, 0x31313100'u32, 0xd1d1d100'u32, 0x17171700'u32, 0x04040400'u32, 0xd7d7d700'u32,
    0x14141400'u32, 0x58585800'u32, 0x3a3a3a00'u32, 0x61616100'u32, 0xdedede00'u32, 0x1b1b1b00'u32, 0x11111100'u32, 0x1c1c1c00'u32,
    0x32323200'u32, 0x0f0f0f00'u32, 0x9c9c9c00'u32, 0x16161600'u32, 0x53535300'u32, 0x18181800'u32, 0xf2f2f200'u32, 0x22222200'u32,
    0xfefefe00'u32, 0x44444400'u32, 0xcfcfcf00'u32, 0xb2b2b200'u32, 0xc3c3c300'u32, 0xb5b5b500'u32, 0x7a7a7a00'u32, 0x91919100'u32,
    0x24242400'u32, 0x08080800'u32, 0xe8e8e800'u32, 0xa8a8a800'u32, 0x60606000'u32, 0xfcfcfc00'u32, 0x69696900'u32, 0x50505000'u32,
    0xaaaaaa00'u32, 0xd0d0d000'u32, 0xa0a0a000'u32, 0x7d7d7d00'u32, 0xa1a1a100'u32, 0x89898900'u32, 0x62626200'u32, 0x97979700'u32,
    0x54545400'u32, 0x5b5b5b00'u32, 0x1e1e1e00'u32, 0x95959500'u32, 0xe0e0e000'u32, 0xffffff00'u32, 0x64646400'u32, 0xd2d2d200'u32,
    0x10101000'u32, 0xc4c4c400'u32, 0x00000000'u32, 0x48484800'u32, 0xa3a3a300'u32, 0xf7f7f700'u32, 0x75757500'u32, 0xdbdbdb00'u32,
    0x8a8a8a00'u32, 0x03030300'u32, 0xe6e6e600'u32, 0xdadada00'u32, 0x09090900'u32, 0x3f3f3f00'u32, 0xdddddd00'u32, 0x94949400'u32,
    0x87878700'u32, 0x5c5c5c00'u32, 0x83838300'u32, 0x02020200'u32, 0xcdcdcd00'u32, 0x4a4a4a00'u32, 0x90909000'u32, 0x33333300'u32,
    0x73737300'u32, 0x67676700'u32, 0xf6f6f600'u32, 0xf3f3f300'u32, 0x9d9d9d00'u32, 0x7f7f7f00'u32, 0xbfbfbf00'u32, 0xe2e2e200'u32,
    0x52525200'u32, 0x9b9b9b00'u32, 0xd8d8d800'u32, 0x26262600'u32, 0xc8c8c800'u32, 0x37373700'u32, 0xc6c6c600'u32, 0x3b3b3b00'u32,
    0x81818100'u32, 0x96969600'u32, 0x6f6f6f00'u32, 0x4b4b4b00'u32, 0x13131300'u32, 0xbebebe00'u32, 0x63636300'u32, 0x2e2e2e00'u32,
    0xe9e9e900'u32, 0x79797900'u32, 0xa7a7a700'u32, 0x8c8c8c00'u32, 0x9f9f9f00'u32, 0x6e6e6e00'u32, 0xbcbcbc00'u32, 0x8e8e8e00'u32,
    0x29292900'u32, 0xf5f5f500'u32, 0xf9f9f900'u32, 0xb6b6b600'u32, 0x2f2f2f00'u32, 0xfdfdfd00'u32, 0xb4b4b400'u32, 0x59595900'u32,
    0x78787800'u32, 0x98989800'u32, 0x06060600'u32, 0x6a6a6a00'u32, 0xe7e7e700'u32, 0x46464600'u32, 0x71717100'u32, 0xbababa00'u32,
    0xd4d4d400'u32, 0x25252500'u32, 0xababab00'u32, 0x42424200'u32, 0x88888800'u32, 0xa2a2a200'u32, 0x8d8d8d00'u32, 0xfafafa00'u32,
    0x72727200'u32, 0x07070700'u32, 0xb9b9b900'u32, 0x55555500'u32, 0xf8f8f800'u32, 0xeeeeee00'u32, 0xacacac00'u32, 0x0a0a0a00'u32,
    0x36363600'u32, 0x49494900'u32, 0x2a2a2a00'u32, 0x68686800'u32, 0x3c3c3c00'u32, 0x38383800'u32, 0xf1f1f100'u32, 0xa4a4a400'u32,
    0x40404000'u32, 0x28282800'u32, 0xd3d3d300'u32, 0x7b7b7b00'u32, 0xbbbbbb00'u32, 0xc9c9c900'u32, 0x43434300'u32, 0xc1c1c100'u32,
    0x15151500'u32, 0xe3e3e300'u32, 0xadadad00'u32, 0xf4f4f400'u32, 0x77777700'u32, 0xc7c7c700'u32, 0x80808000'u32, 0x9e9e9e00'u32,
  ]
  SBox2: array[256, uint32] = [
    0x70700070'u32, 0x2c2c002c'u32, 0xb3b300b3'u32, 0xc0c000c0'u32, 0xe4e400e4'u32, 0x57570057'u32, 0xeaea00ea'u32, 0xaeae00ae'u32,
    0x23230023'u32, 0x6b6b006b'u32, 0x45450045'u32, 0xa5a500a5'u32, 0xeded00ed'u32, 0x4f4f004f'u32, 0x1d1d001d'u32, 0x92920092'u32,
    0x86860086'u32, 0xafaf00af'u32, 0x7c7c007c'u32, 0x1f1f001f'u32, 0x3e3e003e'u32, 0xdcdc00dc'u32, 0x5e5e005e'u32, 0x0b0b000b'u32,
    0xa6a600a6'u32, 0x39390039'u32, 0xd5d500d5'u32, 0x5d5d005d'u32, 0xd9d900d9'u32, 0x5a5a005a'u32, 0x51510051'u32, 0x6c6c006c'u32,
    0x8b8b008b'u32, 0x9a9a009a'u32, 0xfbfb00fb'u32, 0xb0b000b0'u32, 0x74740074'u32, 0x2b2b002b'u32, 0xf0f000f0'u32, 0x84840084'u32,
    0xdfdf00df'u32, 0xcbcb00cb'u32, 0x34340034'u32, 0x76760076'u32, 0x6d6d006d'u32, 0xa9a900a9'u32, 0xd1d100d1'u32, 0x04040004'u32,
    0x14140014'u32, 0x3a3a003a'u32, 0xdede00de'u32, 0x11110011'u32, 0x32320032'u32, 0x9c9c009c'u32, 0x53530053'u32, 0xf2f200f2'u32,
    0xfefe00fe'u32, 0xcfcf00cf'u32, 0xc3c300c3'u32, 0x7a7a007a'u32, 0x24240024'u32, 0xe8e800e8'u32, 0x60600060'u32, 0x69690069'u32,
    0xaaaa00aa'u32, 0xa0a000a0'u32, 0xa1a100a1'u32, 0x62620062'u32, 0x54540054'u32, 0x1e1e001e'u32, 0xe0e000e0'u32, 0x64640064'u32,
    0x10100010'u32, 0x00000000'u32, 0xa3a300a3'u32, 0x75750075'u32, 0x8a8a008a'u32, 0xe6e600e6'u32, 0x09090009'u32, 0xdddd00dd'u32,
    0x87870087'u32, 0x83830083'u32, 0xcdcd00cd'u32, 0x90900090'u32, 0x73730073'u32, 0xf6f600f6'u32, 0x9d9d009d'u32, 0xbfbf00bf'u32,
    0x52520052'u32, 0xd8d800d8'u32, 0xc8c800c8'u32, 0xc6c600c6'u32, 0x81810081'u32, 0x6f6f006f'u32, 0x13130013'u32, 0x63630063'u32,
    0xe9e900e9'u32, 0xa7a700a7'u32, 0x9f9f009f'u32, 0xbcbc00bc'u32, 0x29290029'u32, 0xf9f900f9'u32, 0x2f2f002f'u32, 0xb4b400b4'u32,
    0x78780078'u32, 0x06060006'u32, 0xe7e700e7'u32, 0x71710071'u32, 0xd4d400d4'u32, 0xabab00ab'u32, 0x88880088'u32, 0x8d8d008d'u32,
    0x72720072'u32, 0xb9b900b9'u32, 0xf8f800f8'u32, 0xacac00ac'u32, 0x36360036'u32, 0x2a2a002a'u32, 0x3c3c003c'u32, 0xf1f100f1'u32,
    0x40400040'u32, 0xd3d300d3'u32, 0xbbbb00bb'u32, 0x43430043'u32, 0x15150015'u32, 0xadad00ad'u32, 0x77770077'u32, 0x80800080'u32,
    0x82820082'u32, 0xecec00ec'u32, 0x27270027'u32, 0xe5e500e5'u32, 0x85850085'u32, 0x35350035'u32, 0x0c0c000c'u32, 0x41410041'u32,
    0xefef00ef'u32, 0x93930093'u32, 0x19190019'u32, 0x21210021'u32, 0x0e0e000e'u32, 0x4e4e004e'u32, 0x65650065'u32, 0xbdbd00bd'u32,
    0xb8b800b8'u32, 0x8f8f008f'u32, 0xebeb00eb'u32, 0xcece00ce'u32, 0x30300030'u32, 0x5f5f005f'u32, 0xc5c500c5'u32, 0x1a1a001a'u32,
    0xe1e100e1'u32, 0xcaca00ca'u32, 0x47470047'u32, 0x3d3d003d'u32, 0x01010001'u32, 0xd6d600d6'u32, 0x56560056'u32, 0x4d4d004d'u32,
    0x0d0d000d'u32, 0x66660066'u32, 0xcccc00cc'u32, 0x2d2d002d'u32, 0x12120012'u32, 0x20200020'u32, 0xb1b100b1'u32, 0x99990099'u32,
    0x4c4c004c'u32, 0xc2c200c2'u32, 0x7e7e007e'u32, 0x05050005'u32, 0xb7b700b7'u32, 0x31310031'u32, 0x17170017'u32, 0xd7d700d7'u32,
    0x58580058'u32, 0x61610061'u32, 0x1b1b001b'u32, 0x1c1c001c'u32, 0x0f0f000f'u32, 0x16160016'u32, 0x18180018'u32, 0x22220022'u32,
    0x44440044'u32, 0xb2b200b2'u32, 0xb5b500b5'u32, 0x91910091'u32, 0x08080008'u32, 0xa8a800a8'u32, 0xfcfc00fc'u32, 0x50500050'u32,
    0xd0d000d0'u32, 0x7d7d007d'u32, 0x89890089'u32, 0x97970097'u32, 0x5b5b005b'u32, 0x95950095'u32, 0xffff00ff'u32, 0xd2d200d2'u32,
    0xc4c400c4'u32, 0x48480048'u32, 0xf7f700f7'u32, 0xdbdb00db'u32, 0x03030003'u32, 0xdada00da'u32, 0x3f3f003f'u32, 0x94940094'u32,
    0x5c5c005c'u32, 0x02020002'u32, 0x4a4a004a'u32, 0x33330033'u32, 0x67670067'u32, 0xf3f300f3'u32, 0x7f7f007f'u32, 0xe2e200e2'u32,
    0x9b9b009b'u32, 0x26260026'u32, 0x37370037'u32, 0x3b3b003b'u32, 0x96960096'u32, 0x4b4b004b'u32, 0xbebe00be'u32, 0x2e2e002e'u32,
    0x79790079'u32, 0x8c8c008c'u32, 0x6e6e006e'u32, 0x8e8e008e'u32, 0xf5f500f5'u32, 0xb6b600b6'u32, 0xfdfd00fd'u32, 0x59590059'u32,
    0x98980098'u32, 0x6a6a006a'u32, 0x46460046'u32, 0xbaba00ba'u32, 0x25250025'u32, 0x42420042'u32, 0xa2a200a2'u32, 0xfafa00fa'u32,
    0x07070007'u32, 0x55550055'u32, 0xeeee00ee'u32, 0x0a0a000a'u32, 0x49490049'u32, 0x68680068'u32, 0x38380038'u32, 0xa4a400a4'u32,
    0x28280028'u32, 0x7b7b007b'u32, 0xc9c900c9'u32, 0xc1c100c1'u32, 0xe3e300e3'u32, 0xf4f400f4'u32, 0xc7c700c7'u32, 0x9e9e009e'u32,
  ]
  SBox3: array[256, uint32] = [
    0x00e0e0e0'u32, 0x00050505'u32, 0x00585858'u32, 0x00d9d9d9'u32, 0x00676767'u32, 0x004e4e4e'u32, 0x00818181'u32, 0x00cbcbcb'u32,
    0x00c9c9c9'u32, 0x000b0b0b'u32, 0x00aeaeae'u32, 0x006a6a6a'u32, 0x00d5d5d5'u32, 0x00181818'u32, 0x005d5d5d'u32, 0x00828282'u32,
    0x00464646'u32, 0x00dfdfdf'u32, 0x00d6d6d6'u32, 0x00272727'u32, 0x008a8a8a'u32, 0x00323232'u32, 0x004b4b4b'u32, 0x00424242'u32,
    0x00dbdbdb'u32, 0x001c1c1c'u32, 0x009e9e9e'u32, 0x009c9c9c'u32, 0x003a3a3a'u32, 0x00cacaca'u32, 0x00252525'u32, 0x007b7b7b'u32,
    0x000d0d0d'u32, 0x00717171'u32, 0x005f5f5f'u32, 0x001f1f1f'u32, 0x00f8f8f8'u32, 0x00d7d7d7'u32, 0x003e3e3e'u32, 0x009d9d9d'u32,
    0x007c7c7c'u32, 0x00606060'u32, 0x00b9b9b9'u32, 0x00bebebe'u32, 0x00bcbcbc'u32, 0x008b8b8b'u32, 0x00161616'u32, 0x00343434'u32,
    0x004d4d4d'u32, 0x00c3c3c3'u32, 0x00727272'u32, 0x00959595'u32, 0x00ababab'u32, 0x008e8e8e'u32, 0x00bababa'u32, 0x007a7a7a'u32,
    0x00b3b3b3'u32, 0x00020202'u32, 0x00b4b4b4'u32, 0x00adadad'u32, 0x00a2a2a2'u32, 0x00acacac'u32, 0x00d8d8d8'u32, 0x009a9a9a'u32,
    0x00171717'u32, 0x001a1a1a'u32, 0x00353535'u32, 0x00cccccc'u32, 0x00f7f7f7'u32, 0x00999999'u32, 0x00616161'u32, 0x005a5a5a'u32,
    0x00e8e8e8'u32, 0x00242424'u32, 0x00565656'u32, 0x00404040'u32, 0x00e1e1e1'u32, 0x00636363'u32, 0x00090909'u32, 0x00333333'u32,
    0x00bfbfbf'u32, 0x00989898'u32, 0x00979797'u32, 0x00858585'u32, 0x00686868'u32, 0x00fcfcfc'u32, 0x00ececec'u32, 0x000a0a0a'u32,
    0x00dadada'u32, 0x006f6f6f'u32, 0x00535353'u32, 0x00626262'u32, 0x00a3a3a3'u32, 0x002e2e2e'u32, 0x00080808'u32, 0x00afafaf'u32,
    0x00282828'u32, 0x00b0b0b0'u32, 0x00747474'u32, 0x00c2c2c2'u32, 0x00bdbdbd'u32, 0x00363636'u32, 0x00222222'u32, 0x00383838'u32,
    0x00646464'u32, 0x001e1e1e'u32, 0x00393939'u32, 0x002c2c2c'u32, 0x00a6a6a6'u32, 0x00303030'u32, 0x00e5e5e5'u32, 0x00444444'u32,
    0x00fdfdfd'u32, 0x00888888'u32, 0x009f9f9f'u32, 0x00656565'u32, 0x00878787'u32, 0x006b6b6b'u32, 0x00f4f4f4'u32, 0x00232323'u32,
    0x00484848'u32, 0x00101010'u32, 0x00d1d1d1'u32, 0x00515151'u32, 0x00c0c0c0'u32, 0x00f9f9f9'u32, 0x00d2d2d2'u32, 0x00a0a0a0'u32,
    0x00555555'u32, 0x00a1a1a1'u32, 0x00414141'u32, 0x00fafafa'u32, 0x00434343'u32, 0x00131313'u32, 0x00c4c4c4'u32, 0x002f2f2f'u32,
    0x00a8a8a8'u32, 0x00b6b6b6'u32, 0x003c3c3c'u32, 0x002b2b2b'u32, 0x00c1c1c1'u32, 0x00ffffff'u32, 0x00c8c8c8'u32, 0x00a5a5a5'u32,
    0x00202020'u32, 0x00898989'u32, 0x00000000'u32, 0x00909090'u32, 0x00474747'u32, 0x00efefef'u32, 0x00eaeaea'u32, 0x00b7b7b7'u32,
    0x00151515'u32, 0x00060606'u32, 0x00cdcdcd'u32, 0x00b5b5b5'u32, 0x00121212'u32, 0x007e7e7e'u32, 0x00bbbbbb'u32, 0x00292929'u32,
    0x000f0f0f'u32, 0x00b8b8b8'u32, 0x00070707'u32, 0x00040404'u32, 0x009b9b9b'u32, 0x00949494'u32, 0x00212121'u32, 0x00666666'u32,
    0x00e6e6e6'u32, 0x00cecece'u32, 0x00ededed'u32, 0x00e7e7e7'u32, 0x003b3b3b'u32, 0x00fefefe'u32, 0x007f7f7f'u32, 0x00c5c5c5'u32,
    0x00a4a4a4'u32, 0x00373737'u32, 0x00b1b1b1'u32, 0x004c4c4c'u32, 0x00919191'u32, 0x006e6e6e'u32, 0x008d8d8d'u32, 0x00767676'u32,
    0x00030303'u32, 0x002d2d2d'u32, 0x00dedede'u32, 0x00969696'u32, 0x00262626'u32, 0x007d7d7d'u32, 0x00c6c6c6'u32, 0x005c5c5c'u32,
    0x00d3d3d3'u32, 0x00f2f2f2'u32, 0x004f4f4f'u32, 0x00191919'u32, 0x003f3f3f'u32, 0x00dcdcdc'u32, 0x00797979'u32, 0x001d1d1d'u32,
    0x00525252'u32, 0x00ebebeb'u32, 0x00f3f3f3'u32, 0x006d6d6d'u32, 0x005e5e5e'u32, 0x00fbfbfb'u32, 0x00696969'u32, 0x00b2b2b2'u32,
    0x00f0f0f0'u32, 0x00313131'u32, 0x000c0c0c'u32, 0x00d4d4d4'u32, 0x00cfcfcf'u32, 0x008c8c8c'u32, 0x00e2e2e2'u32, 0x00757575'u32,
    0x00a9a9a9'u32, 0x004a4a4a'u32, 0x00575757'u32, 0x00848484'u32, 0x00111111'u32, 0x00454545'u32, 0x001b1b1b'u32, 0x00f5f5f5'u32,
    0x00e4e4e4'u32, 0x000e0e0e'u32, 0x00737373'u32, 0x00aaaaaa'u32, 0x00f1f1f1'u32, 0x00dddddd'u32, 0x00595959'u32, 0x00141414'u32,
    0x006c6c6c'u32, 0x00929292'u32, 0x00545454'u32, 0x00d0d0d0'u32, 0x00787878'u32, 0x00707070'u32, 0x00e3e3e3'u32, 0x00494949'u32,
    0x00808080'u32, 0x00505050'u32, 0x00a7a7a7'u32, 0x00f6f6f6'u32, 0x00777777'u32, 0x00939393'u32, 0x00868686'u32, 0x00838383'u32,
    0x002a2a2a'u32, 0x00c7c7c7'u32, 0x005b5b5b'u32, 0x00e9e9e9'u32, 0x00eeeeee'u32, 0x008f8f8f'u32, 0x00010101'u32, 0x003d3d3d'u32,
  ]
  SBox4: array[256, uint32] = [
    0x38003838'u32, 0x41004141'u32, 0x16001616'u32, 0x76007676'u32, 0xd900d9d9'u32, 0x93009393'u32, 0x60006060'u32, 0xf200f2f2'u32,
    0x72007272'u32, 0xc200c2c2'u32, 0xab00abab'u32, 0x9a009a9a'u32, 0x75007575'u32, 0x06000606'u32, 0x57005757'u32, 0xa000a0a0'u32,
    0x91009191'u32, 0xf700f7f7'u32, 0xb500b5b5'u32, 0xc900c9c9'u32, 0xa200a2a2'u32, 0x8c008c8c'u32, 0xd200d2d2'u32, 0x90009090'u32,
    0xf600f6f6'u32, 0x07000707'u32, 0xa700a7a7'u32, 0x27002727'u32, 0x8e008e8e'u32, 0xb200b2b2'u32, 0x49004949'u32, 0xde00dede'u32,
    0x43004343'u32, 0x5c005c5c'u32, 0xd700d7d7'u32, 0xc700c7c7'u32, 0x3e003e3e'u32, 0xf500f5f5'u32, 0x8f008f8f'u32, 0x67006767'u32,
    0x1f001f1f'u32, 0x18001818'u32, 0x6e006e6e'u32, 0xaf00afaf'u32, 0x2f002f2f'u32, 0xe200e2e2'u32, 0x85008585'u32, 0x0d000d0d'u32,
    0x53005353'u32, 0xf000f0f0'u32, 0x9c009c9c'u32, 0x65006565'u32, 0xea00eaea'u32, 0xa300a3a3'u32, 0xae00aeae'u32, 0x9e009e9e'u32,
    0xec00ecec'u32, 0x80008080'u32, 0x2d002d2d'u32, 0x6b006b6b'u32, 0xa800a8a8'u32, 0x2b002b2b'u32, 0x36003636'u32, 0xa600a6a6'u32,
    0xc500c5c5'u32, 0x86008686'u32, 0x4d004d4d'u32, 0x33003333'u32, 0xfd00fdfd'u32, 0x66006666'u32, 0x58005858'u32, 0x96009696'u32,
    0x3a003a3a'u32, 0x09000909'u32, 0x95009595'u32, 0x10001010'u32, 0x78007878'u32, 0xd800d8d8'u32, 0x42004242'u32, 0xcc00cccc'u32,
    0xef00efef'u32, 0x26002626'u32, 0xe500e5e5'u32, 0x61006161'u32, 0x1a001a1a'u32, 0x3f003f3f'u32, 0x3b003b3b'u32, 0x82008282'u32,
    0xb600b6b6'u32, 0xdb00dbdb'u32, 0xd400d4d4'u32, 0x98009898'u32, 0xe800e8e8'u32, 0x8b008b8b'u32, 0x02000202'u32, 0xeb00ebeb'u32,
    0x0a000a0a'u32, 0x2c002c2c'u32, 0x1d001d1d'u32, 0xb000b0b0'u32, 0x6f006f6f'u32, 0x8d008d8d'u32, 0x88008888'u32, 0x0e000e0e'u32,
    0x19001919'u32, 0x87008787'u32, 0x4e004e4e'u32, 0x0b000b0b'u32, 0xa900a9a9'u32, 0x0c000c0c'u32, 0x79007979'u32, 0x11001111'u32,
    0x7f007f7f'u32, 0x22002222'u32, 0xe700e7e7'u32, 0x59005959'u32, 0xe100e1e1'u32, 0xda00dada'u32, 0x3d003d3d'u32, 0xc800c8c8'u32,
    0x12001212'u32, 0x04000404'u32, 0x74007474'u32, 0x54005454'u32, 0x30003030'u32, 0x7e007e7e'u32, 0xb400b4b4'u32, 0x28002828'u32,
    0x55005555'u32, 0x68006868'u32, 0x50005050'u32, 0xbe00bebe'u32, 0xd000d0d0'u32, 0xc400c4c4'u32, 0x31003131'u32, 0xcb00cbcb'u32,
    0x2a002a2a'u32, 0xad00adad'u32, 0x0f000f0f'u32, 0xca00caca'u32, 0x70007070'u32, 0xff00ffff'u32, 0x32003232'u32, 0x69006969'u32,
    0x08000808'u32, 0x62006262'u32, 0x00000000'u32, 0x24002424'u32, 0xd100d1d1'u32, 0xfb00fbfb'u32, 0xba00baba'u32, 0xed00eded'u32,
    0x45004545'u32, 0x81008181'u32, 0x73007373'u32, 0x6d006d6d'u32, 0x84008484'u32, 0x9f009f9f'u32, 0xee00eeee'u32, 0x4a004a4a'u32,
    0xc300c3c3'u32, 0x2e002e2e'u32, 0xc100c1c1'u32, 0x01000101'u32, 0xe600e6e6'u32, 0x25002525'u32, 0x48004848'u32, 0x99009999'u32,
    0xb900b9b9'u32, 0xb300b3b3'u32, 0x7b007b7b'u32, 0xf900f9f9'u32, 0xce00cece'u32, 0xbf00bfbf'u32, 0xdf00dfdf'u32, 0x71007171'u32,
    0x29002929'u32, 0xcd00cdcd'u32, 0x6c006c6c'u32, 0x13001313'u32, 0x64006464'u32, 0x9b009b9b'u32, 0x63006363'u32, 0x9d009d9d'u32,
    0xc000c0c0'u32, 0x4b004b4b'u32, 0xb700b7b7'u32, 0xa500a5a5'u32, 0x89008989'u32, 0x5f005f5f'u32, 0xb100b1b1'u32, 0x17001717'u32,
    0xf400f4f4'u32, 0xbc00bcbc'u32, 0xd300d3d3'u32, 0x46004646'u32, 0xcf00cfcf'u32, 0x37003737'u32, 0x5e005e5e'u32, 0x47004747'u32,
    0x94009494'u32, 0xfa00fafa'u32, 0xfc00fcfc'u32, 0x5b005b5b'u32, 0x97009797'u32, 0xfe00fefe'u32, 0x5a005a5a'u32, 0xac00acac'u32,
    0x3c003c3c'u32, 0x4c004c4c'u32, 0x03000303'u32, 0x35003535'u32, 0xf300f3f3'u32, 0x23002323'u32, 0xb800b8b8'u32, 0x5d005d5d'u32,
    0x6a006a6a'u32, 0x92009292'u32, 0xd500d5d5'u32, 0x21002121'u32, 0x44004444'u32, 0x51005151'u32, 0xc600c6c6'u32, 0x7d007d7d'u32,
    0x39003939'u32, 0x83008383'u32, 0xdc00dcdc'u32, 0xaa00aaaa'u32, 0x7c007c7c'u32, 0x77007777'u32, 0x56005656'u32, 0x05000505'u32,
    0x1b001b1b'u32, 0xa400a4a4'u32, 0x15001515'u32, 0x34003434'u32, 0x1e001e1e'u32, 0x1c001c1c'u32, 0xf800f8f8'u32, 0x52005252'u32,
    0x20002020'u32, 0x14001414'u32, 0xe900e9e9'u32, 0xbd00bdbd'u32, 0xdd00dddd'u32, 0xe400e4e4'u32, 0xa100a1a1'u32, 0xe000e0e0'u32,
    0x8a008a8a'u32, 0xf100f1f1'u32, 0xd600d6d6'u32, 0x7a007a7a'u32, 0xbb00bbbb'u32, 0xe300e3e3'u32, 0x40004040'u32, 0x4f004f4f'u32,
  ]
  SIGMA*: array[12, uint32] = [
    0xa09e667f'u32, 0x3bcc908b'u32, 0xb67ae858'u32, 0x4caa73b2'u32, 0xc6ef372f'u32, 0xe94f82be'u32,
    0x54ff53a5'u32, 0xf1d36f1c'u32, 0x10e527fa'u32, 0xde682d1d'u32, 0xb05688c2'u32, 0xb3e6c1fd'u32
  ]

  Camellia128_BLOCK_SIZE*: int = 16
  Camellia192_BLOCK_SIZE*: int = 16
  Camellia256_BLOCK_SIZE*: int = 16

  Camellia128_KEY_SIZE*: int = 16
  Camellia192_KEY_SIZE*: int = 24
  Camellia256_KEY_SIZE*: int = 32

  Camellia128_ROUND_NUMBER*: int = 18
  Camellia192_ROUND_NUMBER*: int = 24
  Camellia256_ROUND_NUMBER*: int = 24

  Camellia128_ROUND_KEY*: int = 26 * 2
  Camellia192_ROUND_KEY*: int = 34 * 2
  Camellia256_ROUND_KEY*: int = 34 * 2

template roundKey(keyBits: static int): static int = 
  static: doAssert keyBits == 128 or keyBits == 192 or keyBits == 256
  when keyBits == 128:
    Camellia128_ROUND_KEY
  elif keyBits == 192:
    Camellia192_ROUND_KEY
  else:
    Camellia256_ROUND_KEY

type
  CamelliaCtx*[keyBits: static int] = object
    roundKey*: array[roundKey(keyBits), uint32]

  Camellia128Ctx* = CamelliaCtx[128]
  Camellia192Ctx* = CamelliaCtx[192]
  Camellia256Ctx* = CamelliaCtx[256]

template blockSize*[keyBits: static int](ctx: CamelliaCtx[keyBits]): static int = 
  static: doAssert keyBits == 128 or keyBits == 192 or keyBits == 256
  when keyBits == 128:
    Camellia128_BLOCK_SIZE
  elif keyBits == 192:
    Camellia192_BLOCK_SIZE
  else:
    Camellia256_BLOCK_SIZE

template keySize*[keyBits: static int](ctx: CamelliaCtx[keyBits]): static int = 
  static: doAssert keyBits == 128 or keyBits == 192 or keyBits == 256
  when keyBits == 128:
    Camellia128_KEY_SIZE
  elif keyBits == 192:
    Camellia192_KEY_SIZE
  else:
    Camellia256_KEY_SIZE

template roundNumber*[keyBits: static int](ctx: CamelliaCtx[keyBits]): static int = 
  static: doAssert keyBits == 128 or keyBits == 192 or keyBits == 256
  when keyBits == 128:
    Camellia128_ROUND_NUMBER
  elif keyBits == 192:
    Camellia192_ROUND_NUMBER
  else:
    Camellia256_ROUND_NUMBER

template roundKey*[keyBits: static int](ctx: CamelliaCtx[keyBits]): static int = 
  static: doAssert keyBits == 128 or keyBits == 192 or keyBits == 256
  when keyBits == 128:
    Camellia128_ROUND_KEY
  elif keyBits == 192:
    Camellia192_ROUND_KEY
  else:
    Camellia256_ROUND_KEY

template camelliaRound(s0, s1, s2, s3: var uint32, key0, key1: uint32): void =
  var t0, t1, t2, t3: uint32
  
  t0 = s0 xor key0
  # The local table declarations follow OpenSSL's storage order:
  # SBox1, SBox4, SBox2, SBox3.
  t3 = SBox2[int(t0 and 0xFF'u32)]

  t1 = s1 xor key1
  t3 = t3 xor SBox4[int((t0 shr 8) and 0xFF'u32)]
  t2 = SBox1[int(t1 and 0xFF'u32)]
  t3 = t3 xor SBox3[int((t0 shr 16) and 0xFF'u32)]
  t2 = t2 xor SBox2[int((t1 shr 8) and 0xFF'u32)]
  t3 = t3 xor SBox1[int((t0 shr 24) and 0xFF'u32)]

  t2 = t2 xor t3
  t3 = rotateRightBits(t3, 8)
  t2 = t2 xor SBox4[int((t1 shr 16) and 0xFF'u32)]
  s3 = s3 xor t3
  t2 = t2 xor SBox3[int((t1 shr 24) and 0xFF'u32)]
  s2 = s2 xor t2
  s3 = s3 xor t2

template rotateLeftBits128(s0, s1, s2, s3: var uint32, n: int): void =
  var temp: uint32 = s0 shr (32 - n)
  s0 = (s0 shl n) or (s1 shr (32 - n))
  s1 = (s1 shl n) or (s2 shr (32 - n))
  s2 = (s2 shl n) or (s3 shr (32 - n))
  s3 = (s3 shl n) or temp
#[
template camelliaInitC[N, keyBits: static int](ctx: CamelliaCtx[keyBits], key: slicearray[N, uint8]): void =
  var s0, s1, s2, s3: uint32

  fromBytesBE(key.toSliceArray(0, 3), s0)
  fromBytesBE(key.toSliceArray(4, 7), s1)
  fromBytesBE(key.toSliceArray(8, 11), s2)
  fromBytesBE(key.toSliceArray(12, 15), s3)

  ctx.roundKey[0] = s0
  ctx.roundKey[1] = s1
  ctx.roundKey[2] = s2
  ctx.roundKey[3] = s3

  when keyBits != 128:
    fromBytesBE(key.toSliceArray(16, 19), s0)
    fromBytesBE(key.toSliceArray(20, 23), s1)

    when keyBits == 192:
      s2 = not s0
      s3 = not s1
    else:
      fromBytesBE(key.toSliceArray(24, 27), s2)
      fromBytesBE(key.toSliceArray(28, 31), s3)

    ctx.roundKey[8] = s0
    ctx.roundKey[9] = s1
    ctx.roundKey[10] = s2
    ctx.roundKey[11] = s3

    s0 = s0 xor ctx.roundKey[0]
    s1 = s1 xor ctx.roundKey[1]
    s2 = s2 xor ctx.roundKey[2]
    s3 = s3 xor ctx.roundKey[3]

  camelliaRound(s0, s1, s2, s3, SIGMA[0], SIGMA[1])
  camelliaRound(s2, s3, s0, s1, SIGMA[2], SIGMA[3])

  s0 = s0 xor ctx.roundKey[0]
  s1 = s1 xor ctx.roundKey[1]
  s2 = s2 xor ctx.roundKey[2]
  s3 = s3 xor ctx.roundKey[3]

  camelliaRound(s0, s1, s2, s3, SIGMA[4], SIGMA[5])
  camelliaRound(s2, s3, s0, s1, SIGMA[6], SIGMA[7])

  when keyBits == 128:
    ctx.roundKey[4] = s0; ctx.roundKey[5] = s1; ctx.roundKey[6] = s2; ctx.roundKey[7] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[12] = s0; ctx.roundKey[13] = s1; ctx.roundKey[14] = s2; ctx.roundKey[15] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[16] = s0; ctx.roundKey[17] = s1; ctx.roundKey[18] = s2; ctx.roundKey[19] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[24] = s0; ctx.roundKey[25] = s1
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[28] = s0; ctx.roundKey[29] = s1; ctx.roundKey[30] = s2; ctx.roundKey[31] = s3
    rotateLeftBits128(s1, s2, s3, s0, 2)
    ctx.roundKey[40] = s1; ctx.roundKey[41] = s2; ctx.roundKey[42] = s3; ctx.roundKey[43] = s0
    rotateLeftBits128(s1, s2, s3, s0, 17)
    ctx.roundKey[48] = s1; ctx.roundKey[49] = s2; ctx.roundKey[50] = s3; ctx.roundKey[51] = s0

    s0 = ctx.roundKey[0]; s1 = ctx.roundKey[1]; s2 = ctx.roundKey[2]; s3 = ctx.roundKey[3]
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[8] = s0; ctx.roundKey[9] = s1; ctx.roundKey[10] = s2; ctx.roundKey[11] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[20] = s0; ctx.roundKey[21] = s1; ctx.roundKey[22] = s2; ctx.roundKey[23] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[26] = s2; ctx.roundKey[27] = s3
    rotateLeftBits128(s0, s1, s2, s3, 17)
    ctx.roundKey[32] = s0; ctx.roundKey[33] = s1; ctx.roundKey[34] = s2; ctx.roundKey[35] = s3
    rotateLeftBits128(s0, s1, s2, s3, 17)
    ctx.roundKey[36] = s0; ctx.roundKey[37] = s1; ctx.roundKey[38] = s2; ctx.roundKey[39] = s3
    rotateLeftBits128(s0, s1, s2, s3, 17)
    ctx.roundKey[44] = s0; ctx.roundKey[45] = s1; ctx.roundKey[46] = s2; ctx.roundKey[47] = s3
  else:
    ctx.roundKey[12] = s0; ctx.roundKey[13] = s1; ctx.roundKey[14] = s2; ctx.roundKey[15] = s3

    s0 = s0 xor ctx.roundKey[8]
    s1 = s1 xor ctx.roundKey[9]
    s2 = s2 xor ctx.roundKey[10]
    s3 = s3 xor ctx.roundKey[11]

    camelliaRound(s0, s1, s2, s3, SIGMA[8], SIGMA[9])
    camelliaRound(s2, s3, s0, s1, SIGMA[10], SIGMA[11])

    ctx.roundKey[4] = s0; ctx.roundKey[5] = s1; ctx.roundKey[6] = s2; ctx.roundKey[7] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[20] = s0; ctx.roundKey[21] = s1; ctx.roundKey[22] = s2; ctx.roundKey[23] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[40] = s0; ctx.roundKey[41] = s1; ctx.roundKey[42] = s2; ctx.roundKey[43] = s3
    rotateLeftBits128(s1, s2, s3, s0, 19)
    ctx.roundKey[64] = s1; ctx.roundKey[65] = s2; ctx.roundKey[66] = s3; ctx.roundKey[67] = s0

    s0 = ctx.roundKey[8]; s1 = ctx.roundKey[9]; s2 = ctx.roundKey[10]; s3 = ctx.roundKey[11]
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[8] = s0; ctx.roundKey[9] = s1; ctx.roundKey[10] = s2; ctx.roundKey[11] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[16] = s0; ctx.roundKey[17] = s1; ctx.roundKey[18] = s2; ctx.roundKey[19] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[36] = s0; ctx.roundKey[37] = s1; ctx.roundKey[38] = s2; ctx.roundKey[39] = s3
    rotateLeftBits128(s1, s2, s3, s0, 2)
    ctx.roundKey[52] = s1; ctx.roundKey[53] = s2; ctx.roundKey[54] = s3; ctx.roundKey[55] = s0

    s0 = ctx.roundKey[12]; s1 = ctx.roundKey[13]; s2 = ctx.roundKey[14]; s3 = ctx.roundKey[15]
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[12] = s0; ctx.roundKey[13] = s1; ctx.roundKey[14] = s2; ctx.roundKey[15] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[28] = s0; ctx.roundKey[29] = s1; ctx.roundKey[30] = s2; ctx.roundKey[31] = s3
    ctx.roundKey[48] = s1; ctx.roundKey[49] = s2; ctx.roundKey[50] = s3; ctx.roundKey[51] = s0
    rotateLeftBits128(s1, s2, s3, s0, 17)
    ctx.roundKey[56] = s1; ctx.roundKey[57] = s2; ctx.roundKey[58] = s3; ctx.roundKey[59] = s0

    s0 = ctx.roundKey[0]; s1 = ctx.roundKey[1]; s2 = ctx.roundKey[2]; s3 = ctx.roundKey[3]
    rotateLeftBits128(s1, s2, s3, s0, 13)
    ctx.roundKey[24] = s1; ctx.roundKey[25] = s2; ctx.roundKey[26] = s3; ctx.roundKey[27] = s0
    rotateLeftBits128(s1, s2, s3, s0, 15)
    ctx.roundKey[32] = s1; ctx.roundKey[33] = s2; ctx.roundKey[34] = s3; ctx.roundKey[35] = s0
    rotateLeftBits128(s1, s2, s3, s0, 17)
    ctx.roundKey[44] = s1; ctx.roundKey[45] = s2; ctx.roundKey[46] = s3; ctx.roundKey[47] = s0
    rotateLeftBits128(s2, s3, s0, s1, 2)
    ctx.roundKey[60] = s2; ctx.roundKey[61] = s3; ctx.roundKey[62] = s0; ctx.roundKey[63] = s1
]#

template camelliaInitC[N, keyBits: static int](ctx: CamelliaCtx[keyBits], key: slicearray[N, uint8]): void =
  var s0, s1, s2, s3: uint32

  fromBytesBE(key.toSliceArray(0, 3), s0)
  fromBytesBE(key.toSliceArray(4, 7), s1)
  fromBytesBE(key.toSliceArray(8, 11), s2)
  fromBytesBE(key.toSliceArray(12, 15), s3)

  ctx.roundKey[0] = s0
  ctx.roundKey[1] = s1
  ctx.roundKey[2] = s2
  ctx.roundKey[3] = s3

  when keyBits != 128:
    fromBytesBE(key.toSliceArray(16, 19), s0)
    fromBytesBE(key.toSliceArray(20, 23), s1)

    when keyBits == 192:
      s2 = not s0
      s3 = not s1
    else:
      fromBytesBE(key.toSliceArray(24, 27), s2)
      fromBytesBE(key.toSliceArray(28, 31), s3)

    ctx.roundKey[8] = s0
    ctx.roundKey[9] = s1
    ctx.roundKey[10] = s2
    ctx.roundKey[11] = s3

    s0 = s0 xor ctx.roundKey[0]
    s1 = s1 xor ctx.roundKey[1]
    s2 = s2 xor ctx.roundKey[2]
    s3 = s3 xor ctx.roundKey[3]

  camelliaRound(s0, s1, s2, s3, SIGMA[0], SIGMA[1])
  camelliaRound(s2, s3, s0, s1, SIGMA[2], SIGMA[3])

  s0 = s0 xor ctx.roundKey[0]
  s1 = s1 xor ctx.roundKey[1]
  s2 = s2 xor ctx.roundKey[2]
  s3 = s3 xor ctx.roundKey[3]

  camelliaRound(s0, s1, s2, s3, SIGMA[4], SIGMA[5])
  camelliaRound(s2, s3, s0, s1, SIGMA[6], SIGMA[7])

  when keyBits == 128:
    ctx.roundKey[4] = s0; ctx.roundKey[5] = s1; ctx.roundKey[6] = s2; ctx.roundKey[7] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[12] = s0; ctx.roundKey[13] = s1; ctx.roundKey[14] = s2; ctx.roundKey[15] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[16] = s0; ctx.roundKey[17] = s1; ctx.roundKey[18] = s2; ctx.roundKey[19] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[24] = s0; ctx.roundKey[25] = s1
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[28] = s0; ctx.roundKey[29] = s1; ctx.roundKey[30] = s2; ctx.roundKey[31] = s3
    rotateLeftBits128(s1, s2, s3, s0, 2)
    ctx.roundKey[40] = s1; ctx.roundKey[41] = s2; ctx.roundKey[42] = s3; ctx.roundKey[43] = s0
    rotateLeftBits128(s1, s2, s3, s0, 17)
    ctx.roundKey[48] = s1; ctx.roundKey[49] = s2; ctx.roundKey[50] = s3; ctx.roundKey[51] = s0

    s0 = ctx.roundKey[0]; s1 = ctx.roundKey[1]; s2 = ctx.roundKey[2]; s3 = ctx.roundKey[3]
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[8] = s0; ctx.roundKey[9] = s1; ctx.roundKey[10] = s2; ctx.roundKey[11] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[20] = s0; ctx.roundKey[21] = s1; ctx.roundKey[22] = s2; ctx.roundKey[23] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[26] = s2; ctx.roundKey[27] = s3
    rotateLeftBits128(s0, s1, s2, s3, 17)
    ctx.roundKey[32] = s0; ctx.roundKey[33] = s1; ctx.roundKey[34] = s2; ctx.roundKey[35] = s3
    rotateLeftBits128(s0, s1, s2, s3, 17)
    ctx.roundKey[36] = s0; ctx.roundKey[37] = s1; ctx.roundKey[38] = s2; ctx.roundKey[39] = s3
    rotateLeftBits128(s0, s1, s2, s3, 17)
    ctx.roundKey[44] = s0; ctx.roundKey[45] = s1; ctx.roundKey[46] = s2; ctx.roundKey[47] = s3
  else:
    ctx.roundKey[12] = s0; ctx.roundKey[13] = s1; ctx.roundKey[14] = s2; ctx.roundKey[15] = s3

    s0 = s0 xor ctx.roundKey[8]
    s1 = s1 xor ctx.roundKey[9]
    s2 = s2 xor ctx.roundKey[10]
    s3 = s3 xor ctx.roundKey[11]

    camelliaRound(s0, s1, s2, s3, SIGMA[8], SIGMA[9])
    camelliaRound(s2, s3, s0, s1, SIGMA[10], SIGMA[11])

    ctx.roundKey[4] = s0; ctx.roundKey[5] = s1; ctx.roundKey[6] = s2; ctx.roundKey[7] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[20] = s0; ctx.roundKey[21] = s1; ctx.roundKey[22] = s2; ctx.roundKey[23] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[40] = s0; ctx.roundKey[41] = s1; ctx.roundKey[42] = s2; ctx.roundKey[43] = s3
    rotateLeftBits128(s1, s2, s3, s0, 19)
    ctx.roundKey[64] = s1; ctx.roundKey[65] = s2; ctx.roundKey[66] = s3; ctx.roundKey[67] = s0

    s0 = ctx.roundKey[8]; s1 = ctx.roundKey[9]; s2 = ctx.roundKey[10]; s3 = ctx.roundKey[11]
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[8] = s0; ctx.roundKey[9] = s1; ctx.roundKey[10] = s2; ctx.roundKey[11] = s3
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[16] = s0; ctx.roundKey[17] = s1; ctx.roundKey[18] = s2; ctx.roundKey[19] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[36] = s0; ctx.roundKey[37] = s1; ctx.roundKey[38] = s2; ctx.roundKey[39] = s3
    rotateLeftBits128(s1, s2, s3, s0, 2)
    ctx.roundKey[52] = s1; ctx.roundKey[53] = s2; ctx.roundKey[54] = s3; ctx.roundKey[55] = s0

    s0 = ctx.roundKey[12]; s1 = ctx.roundKey[13]; s2 = ctx.roundKey[14]; s3 = ctx.roundKey[15]
    rotateLeftBits128(s0, s1, s2, s3, 15)
    ctx.roundKey[12] = s0; ctx.roundKey[13] = s1; ctx.roundKey[14] = s2; ctx.roundKey[15] = s3
    rotateLeftBits128(s0, s1, s2, s3, 30)
    ctx.roundKey[28] = s0; ctx.roundKey[29] = s1; ctx.roundKey[30] = s2; ctx.roundKey[31] = s3

    ctx.roundKey[48] = s1; ctx.roundKey[49] = s2; ctx.roundKey[50] = s3; ctx.roundKey[51] = s0
    rotateLeftBits128(s1, s2, s3, s0, 17)
    ctx.roundKey[56] = s1; ctx.roundKey[57] = s2; ctx.roundKey[58] = s3; ctx.roundKey[59] = s0

    s0 = ctx.roundKey[0]; s1 = ctx.roundKey[1]; s2 = ctx.roundKey[2]; s3 = ctx.roundKey[3]
    rotateLeftBits128(s1, s2, s3, s0, 13)
    ctx.roundKey[24] = s1; ctx.roundKey[25] = s2; ctx.roundKey[26] = s3; ctx.roundKey[27] = s0
    rotateLeftBits128(s1, s2, s3, s0, 15)
    ctx.roundKey[32] = s1; ctx.roundKey[33] = s2; ctx.roundKey[34] = s3; ctx.roundKey[35] = s0
    rotateLeftBits128(s1, s2, s3, s0, 17)
    ctx.roundKey[44] = s1; ctx.roundKey[45] = s2; ctx.roundKey[46] = s3; ctx.roundKey[47] = s0
    rotateLeftBits128(s2, s3, s0, s1, 2)
    ctx.roundKey[60] = s2; ctx.roundKey[61] = s3; ctx.roundKey[62] = s0; ctx.roundKey[63] = s1

template camelliaEncryptC[keyBits: static int](ctx: CamelliaCtx[keyBits], input, output: slicearray[16, uint8]): void =
  var s0, s1, s2, s3: uint32

  const grandRounds: int = when keyBits == 128: 3 else: 4
  const kendIndex: int = grandRounds * 16

  fromBytesBE(input.toSliceArray(0, 3), s0)
  fromBytesBE(input.toSliceArray(4, 7), s1)
  fromBytesBE(input.toSliceArray(8, 11), s2)
  fromBytesBE(input.toSliceArray(12, 15), s3)

  s0 = s0 xor ctx.roundKey[0]
  s1 = s1 xor ctx.roundKey[1]
  s2 = s2 xor ctx.roundKey[2]
  s3 = s3 xor ctx.roundKey[3]

  template rounds(i: static int): void =
    camelliaRound(s0, s1, s2, s3, ctx.roundKey[i + 0], ctx.roundKey[i + 1])
    camelliaRound(s2, s3, s0, s1, ctx.roundKey[i + 2], ctx.roundKey[i + 3])
    camelliaRound(s0, s1, s2, s3, ctx.roundKey[i + 4], ctx.roundKey[i + 5])
    camelliaRound(s2, s3, s0, s1, ctx.roundKey[i + 6], ctx.roundKey[i + 7])
    camelliaRound(s0, s1, s2, s3, ctx.roundKey[i + 8], ctx.roundKey[i + 9])
    camelliaRound(s2, s3, s0, s1, ctx.roundKey[i + 10], ctx.roundKey[i + 11])

  template mix(i: static int): void =
    s1 = s1 xor rotateLeftBits(s0 and ctx.roundKey[i], 1)
    s2 = s2 xor (s3 or ctx.roundKey[i + 3])
    s0 = s0 xor (s1 or ctx.roundKey[i + 1])
    s3 = s3 xor rotateLeftBits(s2 and ctx.roundKey[i + 2], 1)

  rounds(4)
  mix(16)
  rounds(20)
  mix(32)
  rounds(36)
  when keyBits > 128:
    mix(48)
    rounds(52)

  s2 = s2 xor ctx.roundKey[kendIndex + 0]
  s3 = s3 xor ctx.roundKey[kendIndex + 1]
  s0 = s0 xor ctx.roundKey[kendIndex + 2]
  s1 = s1 xor ctx.roundKey[kendIndex + 3]

  toBytesBE(s2, output.toSliceArray(0, 3))
  toBytesBE(s3, output.toSliceArray(4, 7))
  toBytesBE(s0, output.toSliceArray(8, 11))
  toBytesBE(s1, output.toSliceArray(12, 15))

template camelliaDecryptC[keyBits: static int](ctx: CamelliaCtx[keyBits], input, output: slicearray[16, uint8]): void =
  var s0, s1, s2, s3: uint32

  const grandRounds: int = when keyBits == 128: 3 else: 4
  const kendIndex: int = grandRounds * 16 # 128 : 48, 192/256 : 64

  fromBytesBE(input.toSliceArray(0, 3), s0)
  fromBytesBE(input.toSliceArray(4, 7), s1)
  fromBytesBE(input.toSliceArray(8, 11), s2)
  fromBytesBE(input.toSliceArray(12, 15), s3)

  s0 = s0 xor ctx.roundKey[kendIndex + 0]
  s1 = s1 xor ctx.roundKey[kendIndex + 1]
  s2 = s2 xor ctx.roundKey[kendIndex + 2]
  s3 = s3 xor ctx.roundKey[kendIndex + 3]
  
  template rounds(i: static int): void =
    camelliaRound(s0, s1, s2, s3, ctx.roundKey[i + 10], ctx.roundKey[i + 11])
    camelliaRound(s2, s3, s0, s1, ctx.roundKey[i + 8], ctx.roundKey[i + 9])
    camelliaRound(s0, s1, s2, s3, ctx.roundKey[i + 6], ctx.roundKey[i + 7])
    camelliaRound(s2, s3, s0, s1, ctx.roundKey[i + 4], ctx.roundKey[i + 5])
    camelliaRound(s0, s1, s2, s3, ctx.roundKey[i + 2], ctx.roundKey[i + 3])
    camelliaRound(s2, s3, s0, s1, ctx.roundKey[i + 0], ctx.roundKey[i + 1])

  template mix(i: static int): void =
    s1 = s1 xor rotateLeftBits(s0 and ctx.roundKey[i + 2], 1)
    s2 = s2 xor (s3 or ctx.roundKey[i + 1])
    s0 = s0 xor (s1 or ctx.roundKey[i + 3])
    s3 = s3 xor rotateLeftBits(s2 and ctx.roundKey[i + 0], 1)

  when keyBits > 128:
    rounds(52)
    mix(48)
  rounds(36)
  mix(32)
  rounds(20)
  mix(16)
  rounds(4)

  s2 = s2 xor ctx.roundKey[0]
  s3 = s3 xor ctx.roundKey[1]
  s0 = s0 xor ctx.roundKey[2]
  s1 = s1 xor ctx.roundKey[3]

  toBytesBE(s2, output.toSliceArray(0, 3))
  toBytesBE(s3, output.toSliceArray(4, 7))
  toBytesBE(s0, output.toSliceArray(8, 11))
  toBytesBE(s1, output.toSliceArray(12, 15))

# export wrappers
when defined(templateOpt):
  template camellia128Init*(ctx: var Camellia128Ctx, key: array[16, uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 15))
  template camellia128Init*(ctx: var Camellia128Ctx, key: openArray[uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 15))
  template camellia128Init*(ctx: var Camellia128Ctx, key: slicearray[16, uint8]): void =
    camelliaInitC(ctx, key)
  template camellia128Init*(ctx: ptr Camellia128Ctx, key: ptr array[16, uint8]): void =
    camelliaInitC(ctx[], key.toSliceArray(0, 15))

  template camellia128Encrypt*(ctx: Camellia128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia128Encrypt*(ctx: Camellia128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia128Encrypt*(ctx: Camellia128Ctx, input, output: slicearray[16, uint8]): void =
    camelliaEncryptC(ctx, input, output)
  template camellia128Encrypt*(ctx: Camellia128Ctx, input, output: ptr array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template camellia128Decrypt*(ctx: Camellia128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia128Decrypt*(ctx: Camellia128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia128Decrypt*(ctx: Camellia128Ctx, input, output: slicearray[16, uint8]): void =
    camelliaDecryptC(ctx, input, output)
  template camellia128Decrypt*(ctx: Camellia128Ctx, input, output: ptr array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template camellia192Init*(ctx: var Camellia192Ctx, key: array[24, uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 23))
  template camellia192Init*(ctx: var Camellia192Ctx, key: openArray[uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 23))
  template camellia192Init*(ctx: var Camellia192Ctx, key: slicearray[24, uint8]): void =
    camelliaInitC(ctx, key)
  template camellia192Init*(ctx: ptr Camellia192Ctx, key: ptr array[24, uint8]): void =
    camelliaInitC(ctx[], key.toSliceArray(0, 23))

  template camellia192Encrypt*(ctx: Camellia192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia192Encrypt*(ctx: Camellia192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia192Encrypt*(ctx: Camellia192Ctx, input, output: slicearray[16, uint8]): void =
    camelliaEncryptC(ctx, input, output)
  template camellia192Encrypt*(ctx: Camellia192Ctx, input, output: ptr array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template camellia192Decrypt*(ctx: Camellia192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia192Decrypt*(ctx: Camellia192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia192Decrypt*(ctx: Camellia192Ctx, input, output: slicearray[16, uint8]): void =
    camelliaDecryptC(ctx, input, output)
  template camellia192Decrypt*(ctx: Camellia192Ctx, input, output: ptr array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template camellia256Init*(ctx: var Camellia256Ctx, key: array[32, uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 31))
  template camellia256Init*(ctx: var Camellia256Ctx, key: openArray[uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 31))
  template camellia256Init*(ctx: var Camellia256Ctx, key: slicearray[32, uint8]): void =
    camelliaInitC(ctx, key)
  template camellia256Init*(ctx: ptr Camellia256Ctx, key: ptr array[32, uint8]): void =
    camelliaInitC(ctx[], key.toSliceArray(0, 31))

  template camellia256Encrypt*(ctx: Camellia256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia256Encrypt*(ctx: Camellia256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia256Encrypt*(ctx: Camellia256Ctx, input, output: slicearray[16, uint8]): void =
    camelliaEncryptC(ctx, input, output)
  template camellia256Encrypt*(ctx: Camellia256Ctx, input, output: ptr array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template camellia256Decrypt*(ctx: Camellia256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia256Decrypt*(ctx: Camellia256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template camellia256Decrypt*(ctx: Camellia256Ctx, input, output: slicearray[16, uint8]): void =
    camelliaDecryptC(ctx, input, output)
  template camellia256Decrypt*(ctx: Camellia256Ctx, input, output: ptr array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
else:
  proc camellia128Init*(ctx: var Camellia128Ctx, key: array[16, uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 15))
  proc camellia128Init*(ctx: var Camellia128Ctx, key: openArray[uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 15))
  proc camellia128Init*(ctx: var Camellia128Ctx, key: slicearray[16, uint8]): void =
    camelliaInitC(ctx, key)
  proc camellia128Init*(ctx: ptr Camellia128Ctx, key: ptr array[16, uint8]): void =
    camelliaInitC(ctx[], key.toSliceArray(0, 15))

  proc camellia128Encrypt*(ctx: Camellia128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia128Encrypt*(ctx: Camellia128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia128Encrypt*(ctx: Camellia128Ctx, input, output: slicearray[16, uint8]): void =
    camelliaEncryptC(ctx, input, output)
  proc camellia128Encrypt*(ctx: Camellia128Ctx, input, output: ptr array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc camellia128Decrypt*(ctx: Camellia128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia128Decrypt*(ctx: Camellia128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia128Decrypt*(ctx: Camellia128Ctx, input, output: slicearray[16, uint8]): void =
    camelliaDecryptC(ctx, input, output)
  proc camellia128Decrypt*(ctx: Camellia128Ctx, input, output: ptr array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc camellia192Init*(ctx: var Camellia192Ctx, key: array[24, uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 23))
  proc camellia192Init*(ctx: var Camellia192Ctx, key: openArray[uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 23))
  proc camellia192Init*(ctx: var Camellia192Ctx, key: slicearray[24, uint8]): void =
    camelliaInitC(ctx, key)
  proc camellia192Init*(ctx: ptr Camellia192Ctx, key: ptr array[24, uint8]): void =
    camelliaInitC(ctx[], key.toSliceArray(0, 23))

  proc camellia192Encrypt*(ctx: Camellia192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia192Encrypt*(ctx: Camellia192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia192Encrypt*(ctx: Camellia192Ctx, input, output: slicearray[16, uint8]): void =
    camelliaEncryptC(ctx, input, output)
  proc camellia192Encrypt*(ctx: Camellia192Ctx, input, output: ptr array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc camellia192Decrypt*(ctx: Camellia192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia192Decrypt*(ctx: Camellia192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia192Decrypt*(ctx: Camellia192Ctx, input, output: slicearray[16, uint8]): void =
    camelliaDecryptC(ctx, input, output)
  proc camellia192Decrypt*(ctx: Camellia192Ctx, input, output: ptr array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc camellia256Init*(ctx: var Camellia256Ctx, key: array[32, uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 31))
  proc camellia256Init*(ctx: var Camellia256Ctx, key: openArray[uint8]): void =
    camelliaInitC(ctx, key.toSliceArray(0, 31))
  proc camellia256Init*(ctx: var Camellia256Ctx, key: slicearray[32, uint8]): void =
    camelliaInitC(ctx, key)
  proc camellia256Init*(ctx: ptr Camellia256Ctx, key: ptr array[32, uint8]): void =
    camelliaInitC(ctx[], key.toSliceArray(0, 31))

  proc camellia256Encrypt*(ctx: Camellia256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia256Encrypt*(ctx: Camellia256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia256Encrypt*(ctx: Camellia256Ctx, input, output: slicearray[16, uint8]): void =
    camelliaEncryptC(ctx, input, output)
  proc camellia256Encrypt*(ctx: Camellia256Ctx, input, output: ptr array[16, uint8]): void =
    camelliaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc camellia256Decrypt*(ctx: Camellia256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia256Decrypt*(ctx: Camellia256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc camellia256Decrypt*(ctx: Camellia256Ctx, input, output: slicearray[16, uint8]): void =
    camelliaDecryptC(ctx, input, output)
  proc camellia256Decrypt*(ctx: Camellia256Ctx, input, output: ptr array[16, uint8]): void =
    camelliaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
