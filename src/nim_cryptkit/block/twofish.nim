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
  SBox: array[2, array[256, uint8]] = [
    [
      0xA9'u8, 0x67'u8, 0xB3'u8, 0xE8'u8, 0x04'u8, 0xFD'u8, 0xA3'u8, 0x76'u8, 0x9A'u8, 0x92'u8, 0x80'u8, 0x78'u8, 0xE4'u8, 0xDD'u8, 0xD1'u8, 0x38'u8,
      0x0D'u8, 0xC6'u8, 0x35'u8, 0x98'u8, 0x18'u8, 0xF7'u8, 0xEC'u8, 0x6C'u8, 0x43'u8, 0x75'u8, 0x37'u8, 0x26'u8, 0xFA'u8, 0x13'u8, 0x94'u8, 0x48'u8,
      0xF2'u8, 0xD0'u8, 0x8B'u8, 0x30'u8, 0x84'u8, 0x54'u8, 0xDF'u8, 0x23'u8, 0x19'u8, 0x5B'u8, 0x3D'u8, 0x59'u8, 0xF3'u8, 0xAE'u8, 0xA2'u8, 0x82'u8,
      0x63'u8, 0x01'u8, 0x83'u8, 0x2E'u8, 0xD9'u8, 0x51'u8, 0x9B'u8, 0x7C'u8, 0xA6'u8, 0xEB'u8, 0xA5'u8, 0xBE'u8, 0x16'u8, 0x0C'u8, 0xE3'u8, 0x61'u8,
      0xC0'u8, 0x8C'u8, 0x3A'u8, 0xF5'u8, 0x73'u8, 0x2C'u8, 0x25'u8, 0x0B'u8, 0xBB'u8, 0x4E'u8, 0x89'u8, 0x6B'u8, 0x53'u8, 0x6A'u8, 0xB4'u8, 0xF1'u8,
      0xE1'u8, 0xE6'u8, 0xBD'u8, 0x45'u8, 0xE2'u8, 0xF4'u8, 0xB6'u8, 0x66'u8, 0xCC'u8, 0x95'u8, 0x03'u8, 0x56'u8, 0xD4'u8, 0x1C'u8, 0x1E'u8, 0xD7'u8,
      0xFB'u8, 0xC3'u8, 0x8E'u8, 0xB5'u8, 0xE9'u8, 0xCF'u8, 0xBF'u8, 0xBA'u8, 0xEA'u8, 0x77'u8, 0x39'u8, 0xAF'u8, 0x33'u8, 0xC9'u8, 0x62'u8, 0x71'u8,
      0x81'u8, 0x79'u8, 0x09'u8, 0xAD'u8, 0x24'u8, 0xCD'u8, 0xF9'u8, 0xD8'u8, 0xE5'u8, 0xC5'u8, 0xB9'u8, 0x4D'u8, 0x44'u8, 0x08'u8, 0x86'u8, 0xE7'u8,
      0xA1'u8, 0x1D'u8, 0xAA'u8, 0xED'u8, 0x06'u8, 0x70'u8, 0xB2'u8, 0xD2'u8, 0x41'u8, 0x7B'u8, 0xA0'u8, 0x11'u8, 0x31'u8, 0xC2'u8, 0x27'u8, 0x90'u8,
      0x20'u8, 0xF6'u8, 0x60'u8, 0xFF'u8, 0x96'u8, 0x5C'u8, 0xB1'u8, 0xAB'u8, 0x9E'u8, 0x9C'u8, 0x52'u8, 0x1B'u8, 0x5F'u8, 0x93'u8, 0x0A'u8, 0xEF'u8,
      0x91'u8, 0x85'u8, 0x49'u8, 0xEE'u8, 0x2D'u8, 0x4F'u8, 0x8F'u8, 0x3B'u8, 0x47'u8, 0x87'u8, 0x6D'u8, 0x46'u8, 0xD6'u8, 0x3E'u8, 0x69'u8, 0x64'u8,
      0x2A'u8, 0xCE'u8, 0xCB'u8, 0x2F'u8, 0xFC'u8, 0x97'u8, 0x05'u8, 0x7A'u8, 0xAC'u8, 0x7F'u8, 0xD5'u8, 0x1A'u8, 0x4B'u8, 0x0E'u8, 0xA7'u8, 0x5A'u8,
      0x28'u8, 0x14'u8, 0x3F'u8, 0x29'u8, 0x88'u8, 0x3C'u8, 0x4C'u8, 0x02'u8, 0xB8'u8, 0xDA'u8, 0xB0'u8, 0x17'u8, 0x55'u8, 0x1F'u8, 0x8A'u8, 0x7D'u8,
      0x57'u8, 0xC7'u8, 0x8D'u8, 0x74'u8, 0xB7'u8, 0xC4'u8, 0x9F'u8, 0x72'u8, 0x7E'u8, 0x15'u8, 0x22'u8, 0x12'u8, 0x58'u8, 0x07'u8, 0x99'u8, 0x34'u8,
      0x6E'u8, 0x50'u8, 0xDE'u8, 0x68'u8, 0x65'u8, 0xBC'u8, 0xDB'u8, 0xF8'u8, 0xC8'u8, 0xA8'u8, 0x2B'u8, 0x40'u8, 0xDC'u8, 0xFE'u8, 0x32'u8, 0xA4'u8,
      0xCA'u8, 0x10'u8, 0x21'u8, 0xF0'u8, 0xD3'u8, 0x5D'u8, 0x0F'u8, 0x00'u8, 0x6F'u8, 0x9D'u8, 0x36'u8, 0x42'u8, 0x4A'u8, 0x5E'u8, 0xC1'u8, 0xE0'u8
    ],
    [
      0x75'u8, 0xF3'u8, 0xC6'u8, 0xF4'u8, 0xDB'u8, 0x7B'u8, 0xFB'u8, 0xC8'u8, 0x4A'u8, 0xD3'u8, 0xE6'u8, 0x6B'u8, 0x45'u8, 0x7D'u8, 0xE8'u8, 0x4B'u8,
      0xD6'u8, 0x32'u8, 0xD8'u8, 0xFD'u8, 0x37'u8, 0x71'u8, 0xF1'u8, 0xE1'u8, 0x30'u8, 0x0F'u8, 0xF8'u8, 0x1B'u8, 0x87'u8, 0xFA'u8, 0x06'u8, 0x3F'u8,
      0x5E'u8, 0xBA'u8, 0xAE'u8, 0x5B'u8, 0x8A'u8, 0x00'u8, 0xBC'u8, 0x9D'u8, 0x6D'u8, 0xC1'u8, 0xB1'u8, 0x0E'u8, 0x80'u8, 0x5D'u8, 0xD2'u8, 0xD5'u8,
      0xA0'u8, 0x84'u8, 0x07'u8, 0x14'u8, 0xB5'u8, 0x90'u8, 0x2C'u8, 0xA3'u8, 0xB2'u8, 0x73'u8, 0x4C'u8, 0x54'u8, 0x92'u8, 0x74'u8, 0x36'u8, 0x51'u8,
      0x38'u8, 0xB0'u8, 0xBD'u8, 0x5A'u8, 0xFC'u8, 0x60'u8, 0x62'u8, 0x96'u8, 0x6C'u8, 0x42'u8, 0xF7'u8, 0x10'u8, 0x7C'u8, 0x28'u8, 0x27'u8, 0x8C'u8,
      0x13'u8, 0x95'u8, 0x9C'u8, 0xC7'u8, 0x24'u8, 0x46'u8, 0x3B'u8, 0x70'u8, 0xCA'u8, 0xE3'u8, 0x85'u8, 0xCB'u8, 0x11'u8, 0xD0'u8, 0x93'u8, 0xB8'u8,
      0xA6'u8, 0x83'u8, 0x20'u8, 0xFF'u8, 0x9F'u8, 0x77'u8, 0xC3'u8, 0xCC'u8, 0x03'u8, 0x6F'u8, 0x08'u8, 0xBF'u8, 0x40'u8, 0xE7'u8, 0x2B'u8, 0xE2'u8,
      0x79'u8, 0x0C'u8, 0xAA'u8, 0x82'u8, 0x41'u8, 0x3A'u8, 0xEA'u8, 0xB9'u8, 0xE4'u8, 0x9A'u8, 0xA4'u8, 0x97'u8, 0x7E'u8, 0xDA'u8, 0x7A'u8, 0x17'u8,
      0x66'u8, 0x94'u8, 0xA1'u8, 0x1D'u8, 0x3D'u8, 0xF0'u8, 0xDE'u8, 0xB3'u8, 0x0B'u8, 0x72'u8, 0xA7'u8, 0x1C'u8, 0xEF'u8, 0xD1'u8, 0x53'u8, 0x3E'u8,
      0x8F'u8, 0x33'u8, 0x26'u8, 0x5F'u8, 0xEC'u8, 0x76'u8, 0x2A'u8, 0x49'u8, 0x81'u8, 0x88'u8, 0xEE'u8, 0x21'u8, 0xC4'u8, 0x1A'u8, 0xEB'u8, 0xD9'u8,
      0xC5'u8, 0x39'u8, 0x99'u8, 0xCD'u8, 0xAD'u8, 0x31'u8, 0x8B'u8, 0x01'u8, 0x18'u8, 0x23'u8, 0xDD'u8, 0x1F'u8, 0x4E'u8, 0x2D'u8, 0xF9'u8, 0x48'u8,
      0x4F'u8, 0xF2'u8, 0x65'u8, 0x8E'u8, 0x78'u8, 0x5C'u8, 0x58'u8, 0x19'u8, 0x8D'u8, 0xE5'u8, 0x98'u8, 0x57'u8, 0x67'u8, 0x7F'u8, 0x05'u8, 0x64'u8,
      0xAF'u8, 0x63'u8, 0xB6'u8, 0xFE'u8, 0xF5'u8, 0xB7'u8, 0x3C'u8, 0xA5'u8, 0xCE'u8, 0xE9'u8, 0x68'u8, 0x44'u8, 0xE0'u8, 0x4D'u8, 0x43'u8, 0x69'u8,
      0x29'u8, 0x2E'u8, 0xAC'u8, 0x15'u8, 0x59'u8, 0xA8'u8, 0x0A'u8, 0x9E'u8, 0x6E'u8, 0x47'u8, 0xDF'u8, 0x34'u8, 0x35'u8, 0x6A'u8, 0xCF'u8, 0xDC'u8,
      0x22'u8, 0xC9'u8, 0xC0'u8, 0x9B'u8, 0x89'u8, 0xD4'u8, 0xED'u8, 0xAB'u8, 0x12'u8, 0xA2'u8, 0x0D'u8, 0x52'u8, 0xBB'u8, 0x02'u8, 0x2F'u8, 0xA9'u8,
      0xD7'u8, 0x61'u8, 0x1E'u8, 0xB4'u8, 0x50'u8, 0x04'u8, 0xF6'u8, 0xC2'u8, 0x16'u8, 0x25'u8, 0x86'u8, 0x56'u8, 0x55'u8, 0x09'u8, 0xBE'u8, 0x91'u8
    ]
  ]
  Table*: array[4, array[256, uint32]] = [
    [
      0xbcbc3275'u32, 0xecec21f3'u32, 0x202043c6'u32, 0xb3b3c9f4'u32, 0xdada03db'u32, 0x02028b7b'u32, 0xe2e22bfb'u32, 0x9e9efac8'u32,
      0xc9c9ec4a'u32, 0xd4d409d3'u32, 0x18186be6'u32, 0x1e1e9f6b'u32, 0x98980e45'u32, 0xb2b2387d'u32, 0xa6a6d2e8'u32, 0x2626b74b'u32,
      0x3c3c57d6'u32, 0x93938a32'u32, 0x8282eed8'u32, 0x525298fd'u32, 0x7b7bd437'u32, 0xbbbb3771'u32, 0x5b5b97f1'u32, 0x474783e1'u32,
      0x24243c30'u32, 0x5151e20f'u32, 0xbabac6f8'u32, 0x4a4af31b'u32, 0xbfbf4887'u32, 0x0d0d70fa'u32, 0xb0b0b306'u32, 0x7575de3f'u32,
      0xd2d2fd5e'u32, 0x7d7d20ba'u32, 0x666631ae'u32, 0x3a3aa35b'u32, 0x59591c8a'u32, 0x00000000'u32, 0xcdcd93bc'u32, 0x1a1ae09d'u32,
      0xaeae2c6d'u32, 0x7f7fabc1'u32, 0x2b2bc7b1'u32, 0xbebeb90e'u32, 0xe0e0a080'u32, 0x8a8a105d'u32, 0x3b3b52d2'u32, 0x6464bad5'u32,
      0xd8d888a0'u32, 0xe7e7a584'u32, 0x5f5fe807'u32, 0x1b1b1114'u32, 0x2c2cc2b5'u32, 0xfcfcb490'u32, 0x3131272c'u32, 0x808065a3'u32,
      0x73732ab2'u32, 0x0c0c8173'u32, 0x79795f4c'u32, 0x6b6b4154'u32, 0x4b4b0292'u32, 0x53536974'u32, 0x94948f36'u32, 0x83831f51'u32,
      0x2a2a3638'u32, 0xc4c49cb0'u32, 0x2222c8bd'u32, 0xd5d5f85a'u32, 0xbdbdc3fc'u32, 0x48487860'u32, 0xffffce62'u32, 0x4c4c0796'u32,
      0x4141776c'u32, 0xc7c7e642'u32, 0xebeb24f7'u32, 0x1c1c1410'u32, 0x5d5d637c'u32, 0x36362228'u32, 0x6767c027'u32, 0xe9e9af8c'u32,
      0x4444f913'u32, 0x1414ea95'u32, 0xf5f5bb9c'u32, 0xcfcf18c7'u32, 0x3f3f2d24'u32, 0xc0c0e346'u32, 0x7272db3b'u32, 0x54546c70'u32,
      0x29294cca'u32, 0xf0f035e3'u32, 0x0808fe85'u32, 0xc6c617cb'u32, 0xf3f34f11'u32, 0x8c8ce4d0'u32, 0xa4a45993'u32, 0xcaca96b8'u32,
      0x68683ba6'u32, 0xb8b84d83'u32, 0x38382820'u32, 0xe5e52eff'u32, 0xadad569f'u32, 0x0b0b8477'u32, 0xc8c81dc3'u32, 0x9999ffcc'u32,
      0x5858ed03'u32, 0x19199a6f'u32, 0x0e0e0a08'u32, 0x95957ebf'u32, 0x70705040'u32, 0xf7f730e7'u32, 0x6e6ecf2b'u32, 0x1f1f6ee2'u32,
      0xb5b53d79'u32, 0x09090f0c'u32, 0x616134aa'u32, 0x57571682'u32, 0x9f9f0b41'u32, 0x9d9d803a'u32, 0x111164ea'u32, 0x2525cdb9'u32,
      0xafafdde4'u32, 0x4545089a'u32, 0xdfdf8da4'u32, 0xa3a35c97'u32, 0xeaead57e'u32, 0x353558da'u32, 0xededd07a'u32, 0x4343fc17'u32,
      0xf8f8cb66'u32, 0xfbfbb194'u32, 0x3737d3a1'u32, 0xfafa401d'u32, 0xc2c2683d'u32, 0xb4b4ccf0'u32, 0x32325dde'u32, 0x9c9c71b3'u32,
      0x5656e70b'u32, 0xe3e3da72'u32, 0x878760a7'u32, 0x15151b1c'u32, 0xf9f93aef'u32, 0x6363bfd1'u32, 0x3434a953'u32, 0x9a9a853e'u32,
      0xb1b1428f'u32, 0x7c7cd133'u32, 0x88889b26'u32, 0x3d3da65f'u32, 0xa1a1d7ec'u32, 0xe4e4df76'u32, 0x8181942a'u32, 0x91910149'u32,
      0x0f0ffb81'u32, 0xeeeeaa88'u32, 0x161661ee'u32, 0xd7d77321'u32, 0x9797f5c4'u32, 0xa5a5a81a'u32, 0xfefe3feb'u32, 0x6d6db5d9'u32,
      0x7878aec5'u32, 0xc5c56d39'u32, 0x1d1de599'u32, 0x7676a4cd'u32, 0x3e3edcad'u32, 0xcbcb6731'u32, 0xb6b6478b'u32, 0xefef5b01'u32,
      0x12121e18'u32, 0x6060c523'u32, 0x6a6ab0dd'u32, 0x4d4df61f'u32, 0xcecee94e'u32, 0xdede7c2d'u32, 0x55559df9'u32, 0x7e7e5a48'u32,
      0x2121b24f'u32, 0x03037af2'u32, 0xa0a02665'u32, 0x5e5e198e'u32, 0x5a5a6678'u32, 0x65654b5c'u32, 0x62624e58'u32, 0xfdfd4519'u32,
      0x0606f48d'u32, 0x404086e5'u32, 0xf2f2be98'u32, 0x3333ac57'u32, 0x17179067'u32, 0x05058e7f'u32, 0xe8e85e05'u32, 0x4f4f7d64'u32,
      0x89896aaf'u32, 0x10109563'u32, 0x74742fb6'u32, 0x0a0a75fe'u32, 0x5c5c92f5'u32, 0x9b9b74b7'u32, 0x2d2d333c'u32, 0x3030d6a5'u32,
      0x2e2e49ce'u32, 0x494989e9'u32, 0x46467268'u32, 0x77775544'u32, 0xa8a8d8e0'u32, 0x9696044d'u32, 0x2828bd43'u32, 0xa9a92969'u32,
      0xd9d97929'u32, 0x8686912e'u32, 0xd1d187ac'u32, 0xf4f44a15'u32, 0x8d8d1559'u32, 0xd6d682a8'u32, 0xb9b9bc0a'u32, 0x42420d9e'u32,
      0xf6f6c16e'u32, 0x2f2fb847'u32, 0xdddd06df'u32, 0x23233934'u32, 0xcccc6235'u32, 0xf1f1c46a'u32, 0xc1c112cf'u32, 0x8585ebdc'u32,
      0x8f8f9e22'u32, 0x7171a1c9'u32, 0x9090f0c0'u32, 0xaaaa539b'u32, 0x0101f189'u32, 0x8b8be1d4'u32, 0x4e4e8ced'u32, 0x8e8e6fab'u32,
      0xababa212'u32, 0x6f6f3ea2'u32, 0xe6e6540d'u32, 0xdbdbf252'u32, 0x92927bbb'u32, 0xb7b7b602'u32, 0x6969ca2f'u32, 0x3939d9a9'u32,
      0xd3d30cd7'u32, 0xa7a72361'u32, 0xa2a2ad1e'u32, 0xc3c399b4'u32, 0x6c6c4450'u32, 0x07070504'u32, 0x04047ff6'u32, 0x272746c2'u32,
      0xacaca716'u32, 0xd0d07625'u32, 0x50501386'u32, 0xdcdcf756'u32, 0x84841a55'u32, 0xe1e15109'u32, 0x7a7a25be'u32, 0x1313ef91'u32
    ],
    [
      0xa9d93939'u32, 0x67901717'u32, 0xb3719c9c'u32, 0xe8d2a6a6'u32, 0x04050707'u32, 0xfd985252'u32, 0xa3658080'u32, 0x76dfe4e4'u32,
      0x9a084545'u32, 0x92024b4b'u32, 0x80a0e0e0'u32, 0x78665a5a'u32, 0xe4ddafaf'u32, 0xddb06a6a'u32, 0xd1bf6363'u32, 0x38362a2a'u32,
      0x0d54e6e6'u32, 0xc6432020'u32, 0x3562cccc'u32, 0x98bef2f2'u32, 0x181e1212'u32, 0xf724ebeb'u32, 0xecd7a1a1'u32, 0x6c774141'u32,
      0x43bd2828'u32, 0x7532bcbc'u32, 0x37d47b7b'u32, 0x269b8888'u32, 0xfa700d0d'u32, 0x13f94444'u32, 0x94b1fbfb'u32, 0x485a7e7e'u32,
      0xf27a0303'u32, 0xd0e48c8c'u32, 0x8b47b6b6'u32, 0x303c2424'u32, 0x84a5e7e7'u32, 0x54416b6b'u32, 0xdf06dddd'u32, 0x23c56060'u32,
      0x1945fdfd'u32, 0x5ba33a3a'u32, 0x3d68c2c2'u32, 0x59158d8d'u32, 0xf321ecec'u32, 0xae316666'u32, 0xa23e6f6f'u32, 0x82165757'u32,
      0x63951010'u32, 0x015befef'u32, 0x834db8b8'u32, 0x2e918686'u32, 0xd9b56d6d'u32, 0x511f8383'u32, 0x9b53aaaa'u32, 0x7c635d5d'u32,
      0xa63b6868'u32, 0xeb3ffefe'u32, 0xa5d63030'u32, 0xbe257a7a'u32, 0x16a7acac'u32, 0x0c0f0909'u32, 0xe335f0f0'u32, 0x6123a7a7'u32,
      0xc0f09090'u32, 0x8cafe9e9'u32, 0x3a809d9d'u32, 0xf5925c5c'u32, 0x73810c0c'u32, 0x2c273131'u32, 0x2576d0d0'u32, 0x0be75656'u32,
      0xbb7b9292'u32, 0x4ee9cece'u32, 0x89f10101'u32, 0x6b9f1e1e'u32, 0x53a93434'u32, 0x6ac4f1f1'u32, 0xb499c3c3'u32, 0xf1975b5b'u32,
      0xe1834747'u32, 0xe66b1818'u32, 0xbdc82222'u32, 0x450e9898'u32, 0xe26e1f1f'u32, 0xf4c9b3b3'u32, 0xb62f7474'u32, 0x66cbf8f8'u32,
      0xccff9999'u32, 0x95ea1414'u32, 0x03ed5858'u32, 0x56f7dcdc'u32, 0xd4e18b8b'u32, 0x1c1b1515'u32, 0x1eada2a2'u32, 0xd70cd3d3'u32,
      0xfb2be2e2'u32, 0xc31dc8c8'u32, 0x8e195e5e'u32, 0xb5c22c2c'u32, 0xe9894949'u32, 0xcf12c1c1'u32, 0xbf7e9595'u32, 0xba207d7d'u32,
      0xea641111'u32, 0x77840b0b'u32, 0x396dc5c5'u32, 0xaf6a8989'u32, 0x33d17c7c'u32, 0xc9a17171'u32, 0x62ceffff'u32, 0x7137bbbb'u32,
      0x81fb0f0f'u32, 0x793db5b5'u32, 0x0951e1e1'u32, 0xaddc3e3e'u32, 0x242d3f3f'u32, 0xcda47676'u32, 0xf99d5555'u32, 0xd8ee8282'u32,
      0xe5864040'u32, 0xc5ae7878'u32, 0xb9cd2525'u32, 0x4d049696'u32, 0x44557777'u32, 0x080a0e0e'u32, 0x86135050'u32, 0xe730f7f7'u32,
      0xa1d33737'u32, 0x1d40fafa'u32, 0xaa346161'u32, 0xed8c4e4e'u32, 0x06b3b0b0'u32, 0x706c5454'u32, 0xb22a7373'u32, 0xd2523b3b'u32,
      0x410b9f9f'u32, 0x7b8b0202'u32, 0xa088d8d8'u32, 0x114ff3f3'u32, 0x3167cbcb'u32, 0xc2462727'u32, 0x27c06767'u32, 0x90b4fcfc'u32,
      0x20283838'u32, 0xf67f0404'u32, 0x60784848'u32, 0xff2ee5e5'u32, 0x96074c4c'u32, 0x5c4b6565'u32, 0xb1c72b2b'u32, 0xab6f8e8e'u32,
      0x9e0d4242'u32, 0x9cbbf5f5'u32, 0x52f2dbdb'u32, 0x1bf34a4a'u32, 0x5fa63d3d'u32, 0x9359a4a4'u32, 0x0abcb9b9'u32, 0xef3af9f9'u32,
      0x91ef1313'u32, 0x85fe0808'u32, 0x49019191'u32, 0xee611616'u32, 0x2d7cdede'u32, 0x4fb22121'u32, 0x8f42b1b1'u32, 0x3bdb7272'u32,
      0x47b82f2f'u32, 0x8748bfbf'u32, 0x6d2caeae'u32, 0x46e3c0c0'u32, 0xd6573c3c'u32, 0x3e859a9a'u32, 0x6929a9a9'u32, 0x647d4f4f'u32,
      0x2a948181'u32, 0xce492e2e'u32, 0xcb17c6c6'u32, 0x2fca6969'u32, 0xfcc3bdbd'u32, 0x975ca3a3'u32, 0x055ee8e8'u32, 0x7ad0eded'u32,
      0xac87d1d1'u32, 0x7f8e0505'u32, 0xd5ba6464'u32, 0x1aa8a5a5'u32, 0x4bb72626'u32, 0x0eb9bebe'u32, 0xa7608787'u32, 0x5af8d5d5'u32,
      0x28223636'u32, 0x14111b1b'u32, 0x3fde7575'u32, 0x2979d9d9'u32, 0x88aaeeee'u32, 0x3c332d2d'u32, 0x4c5f7979'u32, 0x02b6b7b7'u32,
      0xb896caca'u32, 0xda583535'u32, 0xb09cc4c4'u32, 0x17fc4343'u32, 0x551a8484'u32, 0x1ff64d4d'u32, 0x8a1c5959'u32, 0x7d38b2b2'u32,
      0x57ac3333'u32, 0xc718cfcf'u32, 0x8df40606'u32, 0x74695353'u32, 0xb7749b9b'u32, 0xc4f59797'u32, 0x9f56adad'u32, 0x72dae3e3'u32,
      0x7ed5eaea'u32, 0x154af4f4'u32, 0x229e8f8f'u32, 0x12a2abab'u32, 0x584e6262'u32, 0x07e85f5f'u32, 0x99e51d1d'u32, 0x34392323'u32,
      0x6ec1f6f6'u32, 0x50446c6c'u32, 0xde5d3232'u32, 0x68724646'u32, 0x6526a0a0'u32, 0xbc93cdcd'u32, 0xdb03dada'u32, 0xf8c6baba'u32,
      0xc8fa9e9e'u32, 0xa882d6d6'u32, 0x2bcf6e6e'u32, 0x40507070'u32, 0xdceb8585'u32, 0xfe750a0a'u32, 0x328a9393'u32, 0xa48ddfdf'u32,
      0xca4c2929'u32, 0x10141c1c'u32, 0x2173d7d7'u32, 0xf0ccb4b4'u32, 0xd309d4d4'u32, 0x5d108a8a'u32, 0x0fe25151'u32, 0x00000000'u32,
      0x6f9a1919'u32, 0x9de01a1a'u32, 0x368f9494'u32, 0x42e6c7c7'u32, 0x4aecc9c9'u32, 0x5efdd2d2'u32, 0xc1ab7f7f'u32, 0xe0d8a8a8'u32
    ],
    [
      0xbc75bc32'u32, 0xecf3ec21'u32, 0x20c62043'u32, 0xb3f4b3c9'u32, 0xdadbda03'u32, 0x027b028b'u32, 0xe2fbe22b'u32, 0x9ec89efa'u32,
      0xc94ac9ec'u32, 0xd4d3d409'u32, 0x18e6186b'u32, 0x1e6b1e9f'u32, 0x9845980e'u32, 0xb27db238'u32, 0xa6e8a6d2'u32, 0x264b26b7'u32,
      0x3cd63c57'u32, 0x9332938a'u32, 0x82d882ee'u32, 0x52fd5298'u32, 0x7b377bd4'u32, 0xbb71bb37'u32, 0x5bf15b97'u32, 0x47e14783'u32,
      0x2430243c'u32, 0x510f51e2'u32, 0xbaf8bac6'u32, 0x4a1b4af3'u32, 0xbf87bf48'u32, 0x0dfa0d70'u32, 0xb006b0b3'u32, 0x753f75de'u32,
      0xd25ed2fd'u32, 0x7dba7d20'u32, 0x66ae6631'u32, 0x3a5b3aa3'u32, 0x598a591c'u32, 0x00000000'u32, 0xcdbccd93'u32, 0x1a9d1ae0'u32,
      0xae6dae2c'u32, 0x7fc17fab'u32, 0x2bb12bc7'u32, 0xbe0ebeb9'u32, 0xe080e0a0'u32, 0x8a5d8a10'u32, 0x3bd23b52'u32, 0x64d564ba'u32,
      0xd8a0d888'u32, 0xe784e7a5'u32, 0x5f075fe8'u32, 0x1b141b11'u32, 0x2cb52cc2'u32, 0xfc90fcb4'u32, 0x312c3127'u32, 0x80a38065'u32,
      0x73b2732a'u32, 0x0c730c81'u32, 0x794c795f'u32, 0x6b546b41'u32, 0x4b924b02'u32, 0x53745369'u32, 0x9436948f'u32, 0x8351831f'u32,
      0x2a382a36'u32, 0xc4b0c49c'u32, 0x22bd22c8'u32, 0xd55ad5f8'u32, 0xbdfcbdc3'u32, 0x48604878'u32, 0xff62ffce'u32, 0x4c964c07'u32,
      0x416c4177'u32, 0xc742c7e6'u32, 0xebf7eb24'u32, 0x1c101c14'u32, 0x5d7c5d63'u32, 0x36283622'u32, 0x672767c0'u32, 0xe98ce9af'u32,
      0x441344f9'u32, 0x149514ea'u32, 0xf59cf5bb'u32, 0xcfc7cf18'u32, 0x3f243f2d'u32, 0xc046c0e3'u32, 0x723b72db'u32, 0x5470546c'u32,
      0x29ca294c'u32, 0xf0e3f035'u32, 0x088508fe'u32, 0xc6cbc617'u32, 0xf311f34f'u32, 0x8cd08ce4'u32, 0xa493a459'u32, 0xcab8ca96'u32,
      0x68a6683b'u32, 0xb883b84d'u32, 0x38203828'u32, 0xe5ffe52e'u32, 0xad9fad56'u32, 0x0b770b84'u32, 0xc8c3c81d'u32, 0x99cc99ff'u32,
      0x580358ed'u32, 0x196f199a'u32, 0x0e080e0a'u32, 0x95bf957e'u32, 0x70407050'u32, 0xf7e7f730'u32, 0x6e2b6ecf'u32, 0x1fe21f6e'u32,
      0xb579b53d'u32, 0x090c090f'u32, 0x61aa6134'u32, 0x57825716'u32, 0x9f419f0b'u32, 0x9d3a9d80'u32, 0x11ea1164'u32, 0x25b925cd'u32,
      0xafe4afdd'u32, 0x459a4508'u32, 0xdfa4df8d'u32, 0xa397a35c'u32, 0xea7eead5'u32, 0x35da3558'u32, 0xed7aedd0'u32, 0x431743fc'u32,
      0xf866f8cb'u32, 0xfb94fbb1'u32, 0x37a137d3'u32, 0xfa1dfa40'u32, 0xc23dc268'u32, 0xb4f0b4cc'u32, 0x32de325d'u32, 0x9cb39c71'u32,
      0x560b56e7'u32, 0xe372e3da'u32, 0x87a78760'u32, 0x151c151b'u32, 0xf9eff93a'u32, 0x63d163bf'u32, 0x345334a9'u32, 0x9a3e9a85'u32,
      0xb18fb142'u32, 0x7c337cd1'u32, 0x8826889b'u32, 0x3d5f3da6'u32, 0xa1eca1d7'u32, 0xe476e4df'u32, 0x812a8194'u32, 0x91499101'u32,
      0x0f810ffb'u32, 0xee88eeaa'u32, 0x16ee1661'u32, 0xd721d773'u32, 0x97c497f5'u32, 0xa51aa5a8'u32, 0xfeebfe3f'u32, 0x6dd96db5'u32,
      0x78c578ae'u32, 0xc539c56d'u32, 0x1d991de5'u32, 0x76cd76a4'u32, 0x3ead3edc'u32, 0xcb31cb67'u32, 0xb68bb647'u32, 0xef01ef5b'u32,
      0x1218121e'u32, 0x602360c5'u32, 0x6add6ab0'u32, 0x4d1f4df6'u32, 0xce4ecee9'u32, 0xde2dde7c'u32, 0x55f9559d'u32, 0x7e487e5a'u32,
      0x214f21b2'u32, 0x03f2037a'u32, 0xa065a026'u32, 0x5e8e5e19'u32, 0x5a785a66'u32, 0x655c654b'u32, 0x6258624e'u32, 0xfd19fd45'u32,
      0x068d06f4'u32, 0x40e54086'u32, 0xf298f2be'u32, 0x335733ac'u32, 0x17671790'u32, 0x057f058e'u32, 0xe805e85e'u32, 0x4f644f7d'u32,
      0x89af896a'u32, 0x10631095'u32, 0x74b6742f'u32, 0x0afe0a75'u32, 0x5cf55c92'u32, 0x9bb79b74'u32, 0x2d3c2d33'u32, 0x30a530d6'u32,
      0x2ece2e49'u32, 0x49e94989'u32, 0x46684672'u32, 0x77447755'u32, 0xa8e0a8d8'u32, 0x964d9604'u32, 0x284328bd'u32, 0xa969a929'u32,
      0xd929d979'u32, 0x862e8691'u32, 0xd1acd187'u32, 0xf415f44a'u32, 0x8d598d15'u32, 0xd6a8d682'u32, 0xb90ab9bc'u32, 0x429e420d'u32,
      0xf66ef6c1'u32, 0x2f472fb8'u32, 0xdddfdd06'u32, 0x23342339'u32, 0xcc35cc62'u32, 0xf16af1c4'u32, 0xc1cfc112'u32, 0x85dc85eb'u32,
      0x8f228f9e'u32, 0x71c971a1'u32, 0x90c090f0'u32, 0xaa9baa53'u32, 0x018901f1'u32, 0x8bd48be1'u32, 0x4eed4e8c'u32, 0x8eab8e6f'u32,
      0xab12aba2'u32, 0x6fa26f3e'u32, 0xe60de654'u32, 0xdb52dbf2'u32, 0x92bb927b'u32, 0xb702b7b6'u32, 0x692f69ca'u32, 0x39a939d9'u32,
      0xd3d7d30c'u32, 0xa761a723'u32, 0xa21ea2ad'u32, 0xc3b4c399'u32, 0x6c506c44'u32, 0x07040705'u32, 0x04f6047f'u32, 0x27c22746'u32,
      0xac16aca7'u32, 0xd025d076'u32, 0x50865013'u32, 0xdc56dcf7'u32, 0x8455841a'u32, 0xe109e151'u32, 0x7abe7a25'u32, 0x139113ef'u32
    ],
    [
      0xd939a9d9'u32, 0x90176790'u32, 0x719cb371'u32, 0xd2a6e8d2'u32, 0x05070405'u32, 0x9852fd98'u32, 0x6580a365'u32, 0xdfe476df'u32,
      0x08459a08'u32, 0x024b9202'u32, 0xa0e080a0'u32, 0x665a7866'u32, 0xddafe4dd'u32, 0xb06addb0'u32, 0xbf63d1bf'u32, 0x362a3836'u32,
      0x54e60d54'u32, 0x4320c643'u32, 0x62cc3562'u32, 0xbef298be'u32, 0x1e12181e'u32, 0x24ebf724'u32, 0xd7a1ecd7'u32, 0x77416c77'u32,
      0xbd2843bd'u32, 0x32bc7532'u32, 0xd47b37d4'u32, 0x9b88269b'u32, 0x700dfa70'u32, 0xf94413f9'u32, 0xb1fb94b1'u32, 0x5a7e485a'u32,
      0x7a03f27a'u32, 0xe48cd0e4'u32, 0x47b68b47'u32, 0x3c24303c'u32, 0xa5e784a5'u32, 0x416b5441'u32, 0x06dddf06'u32, 0xc56023c5'u32,
      0x45fd1945'u32, 0xa33a5ba3'u32, 0x68c23d68'u32, 0x158d5915'u32, 0x21ecf321'u32, 0x3166ae31'u32, 0x3e6fa23e'u32, 0x16578216'u32,
      0x95106395'u32, 0x5bef015b'u32, 0x4db8834d'u32, 0x91862e91'u32, 0xb56dd9b5'u32, 0x1f83511f'u32, 0x53aa9b53'u32, 0x635d7c63'u32,
      0x3b68a63b'u32, 0x3ffeeb3f'u32, 0xd630a5d6'u32, 0x257abe25'u32, 0xa7ac16a7'u32, 0x0f090c0f'u32, 0x35f0e335'u32, 0x23a76123'u32,
      0xf090c0f0'u32, 0xafe98caf'u32, 0x809d3a80'u32, 0x925cf592'u32, 0x810c7381'u32, 0x27312c27'u32, 0x76d02576'u32, 0xe7560be7'u32,
      0x7b92bb7b'u32, 0xe9ce4ee9'u32, 0xf10189f1'u32, 0x9f1e6b9f'u32, 0xa93453a9'u32, 0xc4f16ac4'u32, 0x99c3b499'u32, 0x975bf197'u32,
      0x8347e183'u32, 0x6b18e66b'u32, 0xc822bdc8'u32, 0x0e98450e'u32, 0x6e1fe26e'u32, 0xc9b3f4c9'u32, 0x2f74b62f'u32, 0xcbf866cb'u32,
      0xff99ccff'u32, 0xea1495ea'u32, 0xed5803ed'u32, 0xf7dc56f7'u32, 0xe18bd4e1'u32, 0x1b151c1b'u32, 0xada21ead'u32, 0x0cd3d70c'u32,
      0x2be2fb2b'u32, 0x1dc8c31d'u32, 0x195e8e19'u32, 0xc22cb5c2'u32, 0x8949e989'u32, 0x12c1cf12'u32, 0x7e95bf7e'u32, 0x207dba20'u32,
      0x6411ea64'u32, 0x840b7784'u32, 0x6dc5396d'u32, 0x6a89af6a'u32, 0xd17c33d1'u32, 0xa171c9a1'u32, 0xceff62ce'u32, 0x37bb7137'u32,
      0xfb0f81fb'u32, 0x3db5793d'u32, 0x51e10951'u32, 0xdc3eaddc'u32, 0x2d3f242d'u32, 0xa476cda4'u32, 0x9d55f99d'u32, 0xee82d8ee'u32,
      0x8640e586'u32, 0xae78c5ae'u32, 0xcd25b9cd'u32, 0x04964d04'u32, 0x55774455'u32, 0x0a0e080a'u32, 0x13508613'u32, 0x30f7e730'u32,
      0xd337a1d3'u32, 0x40fa1d40'u32, 0x3461aa34'u32, 0x8c4eed8c'u32, 0xb3b006b3'u32, 0x6c54706c'u32, 0x2a73b22a'u32, 0x523bd252'u32,
      0x0b9f410b'u32, 0x8b027b8b'u32, 0x88d8a088'u32, 0x4ff3114f'u32, 0x67cb3167'u32, 0x4627c246'u32, 0xc06727c0'u32, 0xb4fc90b4'u32,
      0x28382028'u32, 0x7f04f67f'u32, 0x78486078'u32, 0x2ee5ff2e'u32, 0x074c9607'u32, 0x4b655c4b'u32, 0xc72bb1c7'u32, 0x6f8eab6f'u32,
      0x0d429e0d'u32, 0xbbf59cbb'u32, 0xf2db52f2'u32, 0xf34a1bf3'u32, 0xa63d5fa6'u32, 0x59a49359'u32, 0xbcb90abc'u32, 0x3af9ef3a'u32,
      0xef1391ef'u32, 0xfe0885fe'u32, 0x01914901'u32, 0x6116ee61'u32, 0x7cde2d7c'u32, 0xb2214fb2'u32, 0x42b18f42'u32, 0xdb723bdb'u32,
      0xb82f47b8'u32, 0x48bf8748'u32, 0x2cae6d2c'u32, 0xe3c046e3'u32, 0x573cd657'u32, 0x859a3e85'u32, 0x29a96929'u32, 0x7d4f647d'u32,
      0x94812a94'u32, 0x492ece49'u32, 0x17c6cb17'u32, 0xca692fca'u32, 0xc3bdfcc3'u32, 0x5ca3975c'u32, 0x5ee8055e'u32, 0xd0ed7ad0'u32,
      0x87d1ac87'u32, 0x8e057f8e'u32, 0xba64d5ba'u32, 0xa8a51aa8'u32, 0xb7264bb7'u32, 0xb9be0eb9'u32, 0x6087a760'u32, 0xf8d55af8'u32,
      0x22362822'u32, 0x111b1411'u32, 0xde753fde'u32, 0x79d92979'u32, 0xaaee88aa'u32, 0x332d3c33'u32, 0x5f794c5f'u32, 0xb6b702b6'u32,
      0x96cab896'u32, 0x5835da58'u32, 0x9cc4b09c'u32, 0xfc4317fc'u32, 0x1a84551a'u32, 0xf64d1ff6'u32, 0x1c598a1c'u32, 0x38b27d38'u32,
      0xac3357ac'u32, 0x18cfc718'u32, 0xf4068df4'u32, 0x69537469'u32, 0x749bb774'u32, 0xf597c4f5'u32, 0x56ad9f56'u32, 0xdae372da'u32,
      0xd5ea7ed5'u32, 0x4af4154a'u32, 0x9e8f229e'u32, 0xa2ab12a2'u32, 0x4e62584e'u32, 0xe85f07e8'u32, 0xe51d99e5'u32, 0x39233439'u32,
      0xc1f66ec1'u32, 0x446c5044'u32, 0x5d32de5d'u32, 0x72466872'u32, 0x26a06526'u32, 0x93cdbc93'u32, 0x03dadb03'u32, 0xc6baf8c6'u32,
      0xfa9ec8fa'u32, 0x82d6a882'u32, 0xcf6e2bcf'u32, 0x50704050'u32, 0xeb85dceb'u32, 0x750afe75'u32, 0x8a93328a'u32, 0x8ddfa48d'u32,
      0x4c29ca4c'u32, 0x141c1014'u32, 0x73d72173'u32, 0xccb4f0cc'u32, 0x09d4d309'u32, 0x108a5d10'u32, 0xe2510fe2'u32, 0x00000000'u32,
      0x9a196f9a'u32, 0xe01a9de0'u32, 0x8f94368f'u32, 0xe6c742e6'u32, 0xecc94aec'u32, 0xfdd25efd'u32, 0xab7fc1ab'u32, 0xd8a8e0d8'u32
    ]
  ]

type
  TwofishCtx*[keySize: static int] = object
    roundKey*: array[40, uint32]
    table*: array[4, array[256, uint32]]

  Twofish128Ctx* = TwofishCtx[16]
  Twofish192Ctx* = TwofishCtx[24]
  Twofish256Ctx* = TwofishCtx[32]

func qWord(a, b, c, d: int, x: uint32): uint32 =
  uint32(SBox[a][int((x shr  0) and 0xFF'u32)]) or
  (uint32(SBox[b][int((x shr  8) and 0xFF'u32)]) shl 8) or
  (uint32(SBox[c][int((x shr 16) and 0xFF'u32)]) shl 16) or
  (uint32(SBox[d][int((x shr 24) and 0xFF'u32)]) shl 24)


func rsMod(c: uint32): uint32 =
  let mask_m: uint32 = 0'u32 - ((c shr 7) and 1'u32)
  let m: uint32 = mask_m and 0x14d'u32
  let c2: uint32 = (c shl 1) xor m

  let mask_n: uint32 = 0'u32 - (c and 1'u32)
  let n: uint32 = mask_n and 0x0a6'u32
  let c1: uint32 = c2 xor (c shr 1) xor n

  c or (c1 shl 8) or (c2 shl 16) or (c1 shl 24)

func reedSolomon(h, l: uint32): uint32 =
  var hi = h
  var lo = l
  for _ in static(0 ..< 8):
    hi = rsMod(hi shr 24) xor (hi shl 8) xor (lo shr 24)
    lo = lo shl 8
  hi

func h0(x: uint32, key: openArray[uint32], words: static int): uint32 =
  var y = x or (x shl 8) or (x shl 16) or (x shl 24)
  when words == 8:
    y = qWord(1, 0, 0, 1, y) xor key[6]
    y = qWord(1, 1, 0, 0, y) xor key[4]
    y = qWord(0, 1, 0, 1, y) xor key[2]
    y = qWord(0, 0, 1, 1, y) xor key[0]
  elif words == 6:
    y = qWord(1, 1, 0, 0, y) xor key[4]
    y = qWord(0, 1, 0, 1, y) xor key[2]
    y = qWord(0, 0, 1, 1, y) xor key[0]
  elif words == 4:
    y = qWord(0, 1, 0, 1, y) xor key[2]
    y = qWord(0, 0, 1, 1, y) xor key[0]
  y

func h(x: uint32, key: openArray[uint32], words: static int): uint32 =
  let y: uint32 = h0(x, key, words)
  Table[0][int((y shr  0) and 0xFF'u32)] xor
  Table[1][int((y shr  8) and 0xFF'u32)] xor
  Table[2][int((y shr 16) and 0xFF'u32)] xor
  Table[3][int((y shr 24) and 0xFF'u32)]

func g1[keySize: static int](ctx: TwofishCtx[keySize], x: uint32): uint32 =
  ctx.table[0][int((x shr  0) and 0xFF'u32)] xor
  ctx.table[1][int((x shr  8) and 0xFF'u32)] xor
  ctx.table[2][int((x shr 16) and 0xFF'u32)] xor
  ctx.table[3][int((x shr 24) and 0xFF'u32)]

func g2[keySize: static int](ctx: TwofishCtx[keySize], x: uint32): uint32 =
  ctx.table[0][int((x shr 24) and 0xFF'u32)] xor
  ctx.table[1][int((x shr  0) and 0xFF'u32)] xor
  ctx.table[2][int((x shr  8) and 0xFF'u32)] xor
  ctx.table[3][int((x shr 16) and 0xFF'u32)]

template twofishInitC[N, keySize: static int](ctx: var TwofishCtx[keySize], key: slicearray[N, uint8]): void =
  var words: array[8, uint32]
  const pairs: int = N div 4
  for i in static(0 ..< pairs):
    fromBytesLE(key.toSliceArray(i * 4 + 0, i * 4 + 3, 4), words[i])
  
  for i in countup(0, 38, 2):
    let a: uint32 = h(uint32(i), words, pairs)
    let b: uint32 = rotateLeftBits(h(uint32(i + 1), words.toOpenArray(1, 7), pairs), 8)
    ctx.roundKey[i] = a + b
    ctx.roundKey[i + 1] = rotateLeftBits(a + (b shl 1), 9)
  
  var s: array[8, uint32]
  const pd: int = pairs div 2
  for i in static(0 ..< pd): 
    s[2 * (pd - i - 1)] = reedSolomon(words[2*i+1], words[2*i])
  
  for i in static(0 ..< 256):
    let y = h0(uint32(i), s, pairs)
    ctx.table[0][i] = Table[0][int((y shr  0) and 0xFF'u32)]
    ctx.table[1][i] = Table[1][int((y shr  8) and 0xFF'u32)]
    ctx.table[2][i] = Table[2][int((y shr 16) and 0xFF'u32)]
    ctx.table[3][i] = Table[3][int((y shr 24) and 0xFF'u32)]


template encRound(ctx: untyped, a, b, c, d: var uint32, r: int): void =
  var x = g1(ctx, a)
  var y = g2(ctx, b)
  x = x + y
  y = y + x + ctx.roundKey[8 + 2 * r + 1]
  c = rotateRightBits(c xor (x + ctx.roundKey[8 + 2 * r]), 1)
  d = rotateLeftBits(d, 1) xor y

template decRound(ctx: untyped, a, b, c, d: var uint32, r: int): void =
  var x = g1(ctx, a)
  var y = g2(ctx, b)
  x = x + y
  y = y + x
  d = rotateRightBits(d xor (y + ctx.roundKey[8 + 2 * r + 1]), 1)
  c = rotateLeftBits(c, 1) xor (x + ctx.roundKey[8 + 2 * r])

template twofishEncryptC[keySize: static int](ctx: TwofishCtx[keySize], input, output: slicearray[16, uint8]): void =
  var a, b, c, d: uint32
  fromBytesLE(input.toSliceArray(0, 3), a)
  fromBytesLE(input.toSliceArray(4, 7), b)
  fromBytesLE(input.toSliceArray(8, 11), c)
  fromBytesLE(input.toSliceArray(12, 15), d)

  a = a xor ctx.roundKey[0]
  b = b xor ctx.roundKey[1]
  c = c xor ctx.roundKey[2]
  d = d xor ctx.roundKey[3]

  unroll(i, 0, 7):
    encRound(ctx, a, b, c, d, 2 * i)
    encRound(ctx, c, d, a, b, 2 * i + 1)

  c = c xor ctx.roundKey[4]
  d = d xor ctx.roundKey[5]
  a = a xor ctx.roundKey[6]
  b = b xor ctx.roundKey[7]

  toBytesLE(c, output.toSliceArray(0, 3))
  toBytesLE(d, output.toSliceArray(4, 7))
  toBytesLE(a, output.toSliceArray(8, 11))
  toBytesLE(b, output.toSliceArray(12, 15))

template twofishDecryptC[keySize: static int](ctx: TwofishCtx[keySize], input, output: slicearray[16, uint8]): void =
  var a, b, c, d: uint32
  fromBytesLE(input.toSliceArray(0, 3), c)
  fromBytesLE(input.toSliceArray(4, 7), d)
  fromBytesLE(input.toSliceArray(8, 11), a)
  fromBytesLE(input.toSliceArray(12, 15), b)

  c = c xor ctx.roundKey[4]
  d = d xor ctx.roundKey[5]
  a = a xor ctx.roundKey[6]
  b = b xor ctx.roundKey[7]

  unroll(i, 7, 0):
    decRound(ctx, c, d, a, b, 2 * i + 1)
    decRound(ctx, a, b, c, d, 2 * i)

  a = a xor ctx.roundKey[0]
  b = b xor ctx.roundKey[1]
  c = c xor ctx.roundKey[2]
  d = d xor ctx.roundKey[3]

  toBytesLE(a, output.toSliceArray(0, 3))
  toBytesLE(b, output.toSliceArray(4, 7))
  toBytesLE(c, output.toSliceArray(8, 11))
  toBytesLE(d, output.toSliceArray(12, 15))

when defined(templateOpt):
  template twofish128Init*(ctx: var Twofish128Ctx, key: array[16, uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 15))
  template twofish128Init*(ctx: var Twofish128Ctx, key: openArray[uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 15))
  template twofish128Init*(ctx: var Twofish128Ctx, key: slicearray[16, uint8]): void = twofishInitC(ctx, key)
  template twofish128Init*(ctx: ptr Twofish128Ctx, key: ptr array[16, uint8]): void = twofishInitC(ctx[], key.toSliceArray(0, 15))

  template twofish128Encrypt*(ctx: Twofish128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish128Encrypt*(ctx: Twofish128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish128Encrypt*(ctx: Twofish128Ctx, input, output: slicearray[16, uint8]): void = twofishEncryptC(ctx, input, output)
  template twofish128Encrypt*(ctx: ptr Twofish128Ctx, input, output: ptr array[16, uint8]): void = twofishEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template twofish128Decrypt*(ctx: Twofish128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish128Decrypt*(ctx: Twofish128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish128Decrypt*(ctx: Twofish128Ctx, input, output: slicearray[16, uint8]): void = twofishDecryptC(ctx, input, output)
  template twofish128Decrypt*(ctx: ptr Twofish128Ctx, input, output: ptr array[16, uint8]): void = twofishDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template twofish192Init*(ctx: var Twofish192Ctx, key: array[24, uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 23))
  template twofish192Init*(ctx: var Twofish192Ctx, key: openArray[uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 23))
  template twofish192Init*(ctx: var Twofish192Ctx, key: slicearray[24, uint8]): void = twofishInitC(ctx, key)
  template twofish192Init*(ctx: ptr Twofish192Ctx, key: ptr array[24, uint8]): void = twofishInitC(ctx[], key.toSliceArray(0, 23))

  template twofish192Encrypt*(ctx: Twofish192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish192Encrypt*(ctx: Twofish192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish192Encrypt*(ctx: Twofish192Ctx, input, output: slicearray[16, uint8]): void = twofishEncryptC(ctx, input, output)
  template twofish192Encrypt*(ctx: ptr Twofish192Ctx, input, output: ptr array[16, uint8]): void = twofishEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template twofish192Decrypt*(ctx: Twofish192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish192Decrypt*(ctx: Twofish192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish192Decrypt*(ctx: Twofish192Ctx, input, output: slicearray[16, uint8]): void = twofishDecryptC(ctx, input, output)
  template twofish192Decrypt*(ctx: ptr Twofish192Ctx, input, output: ptr array[16, uint8]): void = twofishDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template twofish256Init*(ctx: var Twofish256Ctx, key: array[32, uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 31))
  template twofish256Init*(ctx: var Twofish256Ctx, key: openArray[uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 31))
  template twofish256Init*(ctx: var Twofish256Ctx, key: slicearray[32, uint8]): void = twofishInitC(ctx, key)
  template twofish256Init*(ctx: ptr Twofish256Ctx, key: ptr array[32, uint8]): void = twofishInitC(ctx[], key.toSliceArray(0, 31))

  template twofish256Encrypt*(ctx: Twofish256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish256Encrypt*(ctx: Twofish256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish256Encrypt*(ctx: Twofish256Ctx, input, output: slicearray[16, uint8]): void = twofishEncryptC(ctx, input, output)
  template twofish256Encrypt*(ctx: ptr Twofish256Ctx, input, output: ptr array[16, uint8]): void = twofishEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template twofish256Decrypt*(ctx: Twofish256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish256Decrypt*(ctx: Twofish256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template twofish256Decrypt*(ctx: Twofish256Ctx, input, output: slicearray[16, uint8]): void = twofishDecryptC(ctx, input, output)
  template twofish256Decrypt*(ctx: ptr Twofish256Ctx, input, output: ptr array[16, uint8]): void = twofishDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))
else:
  proc twofish128Init*(ctx: var Twofish128Ctx, key: array[16, uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 15))
  proc twofish128Init*(ctx: var Twofish128Ctx, key: openArray[uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 15))
  proc twofish128Init*(ctx: var Twofish128Ctx, key: slicearray[16, uint8]): void = twofishInitC(ctx, key)
  proc twofish128Init*(ctx: ptr Twofish128Ctx, key: ptr array[16, uint8]): void = twofishInitC(ctx[], key.toSliceArray(0, 15))

  proc twofish128Encrypt*(ctx: Twofish128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish128Encrypt*(ctx: Twofish128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish128Encrypt*(ctx: Twofish128Ctx, input, output: slicearray[16, uint8]): void = twofishEncryptC(ctx, input, output)
  proc twofish128Encrypt*(ctx: ptr Twofish128Ctx, input, output: ptr array[16, uint8]): void = twofishEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc twofish128Decrypt*(ctx: Twofish128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish128Decrypt*(ctx: Twofish128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish128Decrypt*(ctx: Twofish128Ctx, input, output: slicearray[16, uint8]): void = twofishDecryptC(ctx, input, output)
  proc twofish128Decrypt*(ctx: ptr Twofish128Ctx, input, output: ptr array[16, uint8]): void = twofishDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc twofish192Init*(ctx: var Twofish192Ctx, key: array[24, uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 23))
  proc twofish192Init*(ctx: var Twofish192Ctx, key: openArray[uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 23))
  proc twofish192Init*(ctx: var Twofish192Ctx, key: slicearray[24, uint8]): void = twofishInitC(ctx, key)
  proc twofish192Init*(ctx: ptr Twofish192Ctx, key: ptr array[24, uint8]): void = twofishInitC(ctx[], key.toSliceArray(0, 23))

  proc twofish192Encrypt*(ctx: Twofish192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish192Encrypt*(ctx: Twofish192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish192Encrypt*(ctx: Twofish192Ctx, input, output: slicearray[16, uint8]): void = twofishEncryptC(ctx, input, output)
  proc twofish192Encrypt*(ctx: ptr Twofish192Ctx, input, output: ptr array[16, uint8]): void = twofishEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc twofish192Decrypt*(ctx: Twofish192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish192Decrypt*(ctx: Twofish192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish192Decrypt*(ctx: Twofish192Ctx, input, output: slicearray[16, uint8]): void = twofishDecryptC(ctx, input, output)
  proc twofish192Decrypt*(ctx: ptr Twofish192Ctx, input, output: ptr array[16, uint8]): void = twofishDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc twofish256Init*(ctx: var Twofish256Ctx, key: array[32, uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 31))
  proc twofish256Init*(ctx: var Twofish256Ctx, key: openArray[uint8]): void = twofishInitC(ctx, key.toSliceArray(0, 31))
  proc twofish256Init*(ctx: var Twofish256Ctx, key: slicearray[32, uint8]): void = twofishInitC(ctx, key)
  proc twofish256Init*(ctx: ptr Twofish256Ctx, key: ptr array[32, uint8]): void = twofishInitC(ctx[], key.toSliceArray(0, 31))

  proc twofish256Encrypt*(ctx: Twofish256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish256Encrypt*(ctx: Twofish256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish256Encrypt*(ctx: Twofish256Ctx, input, output: slicearray[16, uint8]): void = twofishEncryptC(ctx, input, output)
  proc twofish256Encrypt*(ctx: ptr Twofish256Ctx, input, output: ptr array[16, uint8]): void = twofishEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc twofish256Decrypt*(ctx: Twofish256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish256Decrypt*(ctx: Twofish256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = twofishDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc twofish256Decrypt*(ctx: Twofish256Ctx, input, output: slicearray[16, uint8]): void = twofishDecryptC(ctx, input, output)
  proc twofish256Decrypt*(ctx: ptr Twofish256Ctx, input, output: ptr array[16, uint8]): void = twofishDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))
