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
  # declare key constants
  KC: array[16, uint32] = [
    0x9e3779b9'u32, 0x3c6ef373'u32, 0x78dde6e6'u32, 0xf1bbcdcc'u32, 0xe3779b99'u32, 0xc6ef3733'u32, 0x8dde6e67'u32, 0x1bbcdccf'u32,
    0x3779b99e'u32, 0x6ef3733c'u32, 0xdde6e678'u32, 0xbbcdccf1'u32, 0x779b99e3'u32, 0xef3733c6'u32, 0xde6e678d'u32, 0xbcdccf1b'u32
  ]
  # declare SBox 0 ~ 3
  Table: array[4, array[256, uint32]] = [
    [
      0x2989a1a8'u32, 0x05858184'u32, 0x16c6d2d4'u32, 0x13c3d3d0'u32, 0x14445054'u32, 0x1d0d111c'u32, 0x2c8ca0ac'u32, 0x25052124'u32,
      0x1d4d515c'u32, 0x03434340'u32, 0x18081018'u32, 0x1e0e121c'u32, 0x11415150'u32, 0x3cccf0fc'u32, 0x0acac2c8'u32, 0x23436360'u32,
      0x28082028'u32, 0x04444044'u32, 0x20002020'u32, 0x1d8d919c'u32, 0x20c0e0e0'u32, 0x22c2e2e0'u32, 0x08c8c0c8'u32, 0x17071314'u32,
      0x2585a1a4'u32, 0x0f8f838c'u32, 0x03030300'u32, 0x3b4b7378'u32, 0x3b8bb3b8'u32, 0x13031310'u32, 0x12c2d2d0'u32, 0x2ecee2ec'u32,
      0x30407070'u32, 0x0c8c808c'u32, 0x3f0f333c'u32, 0x2888a0a8'u32, 0x32023230'u32, 0x1dcdd1dc'u32, 0x36c6f2f4'u32, 0x34447074'u32,
      0x2ccce0ec'u32, 0x15859194'u32, 0x0b0b0308'u32, 0x17475354'u32, 0x1c4c505c'u32, 0x1b4b5358'u32, 0x3d8db1bc'u32, 0x01010100'u32,
      0x24042024'u32, 0x1c0c101c'u32, 0x33437370'u32, 0x18889098'u32, 0x10001010'u32, 0x0cccc0cc'u32, 0x32c2f2f0'u32, 0x19c9d1d8'u32,
      0x2c0c202c'u32, 0x27c7e3e4'u32, 0x32427270'u32, 0x03838380'u32, 0x1b8b9398'u32, 0x11c1d1d0'u32, 0x06868284'u32, 0x09c9c1c8'u32,
      0x20406060'u32, 0x10405050'u32, 0x2383a3a0'u32, 0x2bcbe3e8'u32, 0x0d0d010c'u32, 0x3686b2b4'u32, 0x1e8e929c'u32, 0x0f4f434c'u32,
      0x3787b3b4'u32, 0x1a4a5258'u32, 0x06c6c2c4'u32, 0x38487078'u32, 0x2686a2a4'u32, 0x12021210'u32, 0x2f8fa3ac'u32, 0x15c5d1d4'u32,
      0x21416160'u32, 0x03c3c3c0'u32, 0x3484b0b4'u32, 0x01414140'u32, 0x12425250'u32, 0x3d4d717c'u32, 0x0d8d818c'u32, 0x08080008'u32,
      0x1f0f131c'u32, 0x19899198'u32, 0x00000000'u32, 0x19091118'u32, 0x04040004'u32, 0x13435350'u32, 0x37c7f3f4'u32, 0x21c1e1e0'u32,
      0x3dcdf1fc'u32, 0x36467274'u32, 0x2f0f232c'u32, 0x27072324'u32, 0x3080b0b0'u32, 0x0b8b8388'u32, 0x0e0e020c'u32, 0x2b8ba3a8'u32,
      0x2282a2a0'u32, 0x2e4e626c'u32, 0x13839390'u32, 0x0d4d414c'u32, 0x29496168'u32, 0x3c4c707c'u32, 0x09090108'u32, 0x0a0a0208'u32,
      0x3f8fb3bc'u32, 0x2fcfe3ec'u32, 0x33c3f3f0'u32, 0x05c5c1c4'u32, 0x07878384'u32, 0x14041014'u32, 0x3ecef2fc'u32, 0x24446064'u32,
      0x1eced2dc'u32, 0x2e0e222c'u32, 0x0b4b4348'u32, 0x1a0a1218'u32, 0x06060204'u32, 0x21012120'u32, 0x2b4b6368'u32, 0x26466264'u32,
      0x02020200'u32, 0x35c5f1f4'u32, 0x12829290'u32, 0x0a8a8288'u32, 0x0c0c000c'u32, 0x3383b3b0'u32, 0x3e4e727c'u32, 0x10c0d0d0'u32,
      0x3a4a7278'u32, 0x07474344'u32, 0x16869294'u32, 0x25c5e1e4'u32, 0x26062224'u32, 0x00808080'u32, 0x2d8da1ac'u32, 0x1fcfd3dc'u32,
      0x2181a1a0'u32, 0x30003030'u32, 0x37073334'u32, 0x2e8ea2ac'u32, 0x36063234'u32, 0x15051114'u32, 0x22022220'u32, 0x38083038'u32,
      0x34c4f0f4'u32, 0x2787a3a4'u32, 0x05454144'u32, 0x0c4c404c'u32, 0x01818180'u32, 0x29c9e1e8'u32, 0x04848084'u32, 0x17879394'u32,
      0x35053134'u32, 0x0bcbc3c8'u32, 0x0ecec2cc'u32, 0x3c0c303c'u32, 0x31417170'u32, 0x11011110'u32, 0x07c7c3c4'u32, 0x09898188'u32,
      0x35457174'u32, 0x3bcbf3f8'u32, 0x1acad2d8'u32, 0x38c8f0f8'u32, 0x14849094'u32, 0x19495158'u32, 0x02828280'u32, 0x04c4c0c4'u32,
      0x3fcff3fc'u32, 0x09494148'u32, 0x39093138'u32, 0x27476364'u32, 0x00c0c0c0'u32, 0x0fcfc3cc'u32, 0x17c7d3d4'u32, 0x3888b0b8'u32,
      0x0f0f030c'u32, 0x0e8e828c'u32, 0x02424240'u32, 0x23032320'u32, 0x11819190'u32, 0x2c4c606c'u32, 0x1bcbd3d8'u32, 0x2484a0a4'u32,
      0x34043034'u32, 0x31c1f1f0'u32, 0x08484048'u32, 0x02c2c2c0'u32, 0x2f4f636c'u32, 0x3d0d313c'u32, 0x2d0d212c'u32, 0x00404040'u32,
      0x3e8eb2bc'u32, 0x3e0e323c'u32, 0x3c8cb0bc'u32, 0x01c1c1c0'u32, 0x2a8aa2a8'u32, 0x3a8ab2b8'u32, 0x0e4e424c'u32, 0x15455154'u32,
      0x3b0b3338'u32, 0x1cccd0dc'u32, 0x28486068'u32, 0x3f4f737c'u32, 0x1c8c909c'u32, 0x18c8d0d8'u32, 0x0a4a4248'u32, 0x16465254'u32,
      0x37477374'u32, 0x2080a0a0'u32, 0x2dcde1ec'u32, 0x06464244'u32, 0x3585b1b4'u32, 0x2b0b2328'u32, 0x25456164'u32, 0x3acaf2f8'u32,
      0x23c3e3e0'u32, 0x3989b1b8'u32, 0x3181b1b0'u32, 0x1f8f939c'u32, 0x1e4e525c'u32, 0x39c9f1f8'u32, 0x26c6e2e4'u32, 0x3282b2b0'u32,
      0x31013130'u32, 0x2acae2e8'u32, 0x2d4d616c'u32, 0x1f4f535c'u32, 0x24c4e0e4'u32, 0x30c0f0f0'u32, 0x0dcdc1cc'u32, 0x08888088'u32,
      0x16061214'u32, 0x3a0a3238'u32, 0x18485058'u32, 0x14c4d0d4'u32, 0x22426260'u32, 0x29092128'u32, 0x07070304'u32, 0x33033330'u32,
      0x28c8e0e8'u32, 0x1b0b1318'u32, 0x05050104'u32, 0x39497178'u32, 0x10809090'u32, 0x2a4a6268'u32, 0x2a0a2228'u32, 0x1a8a9298'u32
    ],
    [
      0x38380830'u32, 0xe828c8e0'u32, 0x2c2d0d21'u32, 0xa42686a2'u32, 0xcc0fcfc3'u32, 0xdc1eced2'u32, 0xb03383b3'u32, 0xb83888b0'u32,
      0xac2f8fa3'u32, 0x60204060'u32, 0x54154551'u32, 0xc407c7c3'u32, 0x44044440'u32, 0x6c2f4f63'u32, 0x682b4b63'u32, 0x581b4b53'u32,
      0xc003c3c3'u32, 0x60224262'u32, 0x30330333'u32, 0xb43585b1'u32, 0x28290921'u32, 0xa02080a0'u32, 0xe022c2e2'u32, 0xa42787a3'u32,
      0xd013c3d3'u32, 0x90118191'u32, 0x10110111'u32, 0x04060602'u32, 0x1c1c0c10'u32, 0xbc3c8cb0'u32, 0x34360632'u32, 0x480b4b43'u32,
      0xec2fcfe3'u32, 0x88088880'u32, 0x6c2c4c60'u32, 0xa82888a0'u32, 0x14170713'u32, 0xc404c4c0'u32, 0x14160612'u32, 0xf434c4f0'u32,
      0xc002c2c2'u32, 0x44054541'u32, 0xe021c1e1'u32, 0xd416c6d2'u32, 0x3c3f0f33'u32, 0x3c3d0d31'u32, 0x8c0e8e82'u32, 0x98188890'u32,
      0x28280820'u32, 0x4c0e4e42'u32, 0xf436c6f2'u32, 0x3c3e0e32'u32, 0xa42585a1'u32, 0xf839c9f1'u32, 0x0c0d0d01'u32, 0xdc1fcfd3'u32,
      0xd818c8d0'u32, 0x282b0b23'u32, 0x64264662'u32, 0x783a4a72'u32, 0x24270723'u32, 0x2c2f0f23'u32, 0xf031c1f1'u32, 0x70324272'u32,
      0x40024242'u32, 0xd414c4d0'u32, 0x40014141'u32, 0xc000c0c0'u32, 0x70334373'u32, 0x64274763'u32, 0xac2c8ca0'u32, 0x880b8b83'u32,
      0xf437c7f3'u32, 0xac2d8da1'u32, 0x80008080'u32, 0x1c1f0f13'u32, 0xc80acac2'u32, 0x2c2c0c20'u32, 0xa82a8aa2'u32, 0x34340430'u32,
      0xd012c2d2'u32, 0x080b0b03'u32, 0xec2ecee2'u32, 0xe829c9e1'u32, 0x5c1d4d51'u32, 0x94148490'u32, 0x18180810'u32, 0xf838c8f0'u32,
      0x54174753'u32, 0xac2e8ea2'u32, 0x08080800'u32, 0xc405c5c1'u32, 0x10130313'u32, 0xcc0dcdc1'u32, 0x84068682'u32, 0xb83989b1'u32,
      0xfc3fcff3'u32, 0x7c3d4d71'u32, 0xc001c1c1'u32, 0x30310131'u32, 0xf435c5f1'u32, 0x880a8a82'u32, 0x682a4a62'u32, 0xb03181b1'u32,
      0xd011c1d1'u32, 0x20200020'u32, 0xd417c7d3'u32, 0x00020202'u32, 0x20220222'u32, 0x04040400'u32, 0x68284860'u32, 0x70314171'u32,
      0x04070703'u32, 0xd81bcbd3'u32, 0x9c1d8d91'u32, 0x98198991'u32, 0x60214161'u32, 0xbc3e8eb2'u32, 0xe426c6e2'u32, 0x58194951'u32,
      0xdc1dcdd1'u32, 0x50114151'u32, 0x90108090'u32, 0xdc1cccd0'u32, 0x981a8a92'u32, 0xa02383a3'u32, 0xa82b8ba3'u32, 0xd010c0d0'u32,
      0x80018181'u32, 0x0c0f0f03'u32, 0x44074743'u32, 0x181a0a12'u32, 0xe023c3e3'u32, 0xec2ccce0'u32, 0x8c0d8d81'u32, 0xbc3f8fb3'u32,
      0x94168692'u32, 0x783b4b73'u32, 0x5c1c4c50'u32, 0xa02282a2'u32, 0xa02181a1'u32, 0x60234363'u32, 0x20230323'u32, 0x4c0d4d41'u32,
      0xc808c8c0'u32, 0x9c1e8e92'u32, 0x9c1c8c90'u32, 0x383a0a32'u32, 0x0c0c0c00'u32, 0x2c2e0e22'u32, 0xb83a8ab2'u32, 0x6c2e4e62'u32,
      0x9c1f8f93'u32, 0x581a4a52'u32, 0xf032c2f2'u32, 0x90128292'u32, 0xf033c3f3'u32, 0x48094941'u32, 0x78384870'u32, 0xcc0cccc0'u32,
      0x14150511'u32, 0xf83bcbf3'u32, 0x70304070'u32, 0x74354571'u32, 0x7c3f4f73'u32, 0x34350531'u32, 0x10100010'u32, 0x00030303'u32,
      0x64244460'u32, 0x6c2d4d61'u32, 0xc406c6c2'u32, 0x74344470'u32, 0xd415c5d1'u32, 0xb43484b0'u32, 0xe82acae2'u32, 0x08090901'u32,
      0x74364672'u32, 0x18190911'u32, 0xfc3ecef2'u32, 0x40004040'u32, 0x10120212'u32, 0xe020c0e0'u32, 0xbc3d8db1'u32, 0x04050501'u32,
      0xf83acaf2'u32, 0x00010101'u32, 0xf030c0f0'u32, 0x282a0a22'u32, 0x5c1e4e52'u32, 0xa82989a1'u32, 0x54164652'u32, 0x40034343'u32,
      0x84058581'u32, 0x14140410'u32, 0x88098981'u32, 0x981b8b93'u32, 0xb03080b0'u32, 0xe425c5e1'u32, 0x48084840'u32, 0x78394971'u32,
      0x94178793'u32, 0xfc3cccf0'u32, 0x1c1e0e12'u32, 0x80028282'u32, 0x20210121'u32, 0x8c0c8c80'u32, 0x181b0b13'u32, 0x5c1f4f53'u32,
      0x74374773'u32, 0x54144450'u32, 0xb03282b2'u32, 0x1c1d0d11'u32, 0x24250521'u32, 0x4c0f4f43'u32, 0x00000000'u32, 0x44064642'u32,
      0xec2dcde1'u32, 0x58184850'u32, 0x50124252'u32, 0xe82bcbe3'u32, 0x7c3e4e72'u32, 0xd81acad2'u32, 0xc809c9c1'u32, 0xfc3dcdf1'u32,
      0x30300030'u32, 0x94158591'u32, 0x64254561'u32, 0x3c3c0c30'u32, 0xb43686b2'u32, 0xe424c4e0'u32, 0xb83b8bb3'u32, 0x7c3c4c70'u32,
      0x0c0e0e02'u32, 0x50104050'u32, 0x38390931'u32, 0x24260622'u32, 0x30320232'u32, 0x84048480'u32, 0x68294961'u32, 0x90138393'u32,
      0x34370733'u32, 0xe427c7e3'u32, 0x24240420'u32, 0xa42484a0'u32, 0xc80bcbc3'u32, 0x50134353'u32, 0x080a0a02'u32, 0x84078783'u32,
      0xd819c9d1'u32, 0x4c0c4c40'u32, 0x80038383'u32, 0x8c0f8f83'u32, 0xcc0ecec2'u32, 0x383b0b33'u32, 0x480a4a42'u32, 0xb43787b3'u32
    ],
    [
      0xa1a82989'u32, 0x81840585'u32, 0xd2d416c6'u32, 0xd3d013c3'u32, 0x50541444'u32, 0x111c1d0d'u32, 0xa0ac2c8c'u32, 0x21242505'u32,
      0x515c1d4d'u32, 0x43400343'u32, 0x10181808'u32, 0x121c1e0e'u32, 0x51501141'u32, 0xf0fc3ccc'u32, 0xc2c80aca'u32, 0x63602343'u32,
      0x20282808'u32, 0x40440444'u32, 0x20202000'u32, 0x919c1d8d'u32, 0xe0e020c0'u32, 0xe2e022c2'u32, 0xc0c808c8'u32, 0x13141707'u32,
      0xa1a42585'u32, 0x838c0f8f'u32, 0x03000303'u32, 0x73783b4b'u32, 0xb3b83b8b'u32, 0x13101303'u32, 0xd2d012c2'u32, 0xe2ec2ece'u32,
      0x70703040'u32, 0x808c0c8c'u32, 0x333c3f0f'u32, 0xa0a82888'u32, 0x32303202'u32, 0xd1dc1dcd'u32, 0xf2f436c6'u32, 0x70743444'u32,
      0xe0ec2ccc'u32, 0x91941585'u32, 0x03080b0b'u32, 0x53541747'u32, 0x505c1c4c'u32, 0x53581b4b'u32, 0xb1bc3d8d'u32, 0x01000101'u32,
      0x20242404'u32, 0x101c1c0c'u32, 0x73703343'u32, 0x90981888'u32, 0x10101000'u32, 0xc0cc0ccc'u32, 0xf2f032c2'u32, 0xd1d819c9'u32,
      0x202c2c0c'u32, 0xe3e427c7'u32, 0x72703242'u32, 0x83800383'u32, 0x93981b8b'u32, 0xd1d011c1'u32, 0x82840686'u32, 0xc1c809c9'u32,
      0x60602040'u32, 0x50501040'u32, 0xa3a02383'u32, 0xe3e82bcb'u32, 0x010c0d0d'u32, 0xb2b43686'u32, 0x929c1e8e'u32, 0x434c0f4f'u32,
      0xb3b43787'u32, 0x52581a4a'u32, 0xc2c406c6'u32, 0x70783848'u32, 0xa2a42686'u32, 0x12101202'u32, 0xa3ac2f8f'u32, 0xd1d415c5'u32,
      0x61602141'u32, 0xc3c003c3'u32, 0xb0b43484'u32, 0x41400141'u32, 0x52501242'u32, 0x717c3d4d'u32, 0x818c0d8d'u32, 0x00080808'u32,
      0x131c1f0f'u32, 0x91981989'u32, 0x00000000'u32, 0x11181909'u32, 0x00040404'u32, 0x53501343'u32, 0xf3f437c7'u32, 0xe1e021c1'u32,
      0xf1fc3dcd'u32, 0x72743646'u32, 0x232c2f0f'u32, 0x23242707'u32, 0xb0b03080'u32, 0x83880b8b'u32, 0x020c0e0e'u32, 0xa3a82b8b'u32,
      0xa2a02282'u32, 0x626c2e4e'u32, 0x93901383'u32, 0x414c0d4d'u32, 0x61682949'u32, 0x707c3c4c'u32, 0x01080909'u32, 0x02080a0a'u32,
      0xb3bc3f8f'u32, 0xe3ec2fcf'u32, 0xf3f033c3'u32, 0xc1c405c5'u32, 0x83840787'u32, 0x10141404'u32, 0xf2fc3ece'u32, 0x60642444'u32,
      0xd2dc1ece'u32, 0x222c2e0e'u32, 0x43480b4b'u32, 0x12181a0a'u32, 0x02040606'u32, 0x21202101'u32, 0x63682b4b'u32, 0x62642646'u32,
      0x02000202'u32, 0xf1f435c5'u32, 0x92901282'u32, 0x82880a8a'u32, 0x000c0c0c'u32, 0xb3b03383'u32, 0x727c3e4e'u32, 0xd0d010c0'u32,
      0x72783a4a'u32, 0x43440747'u32, 0x92941686'u32, 0xe1e425c5'u32, 0x22242606'u32, 0x80800080'u32, 0xa1ac2d8d'u32, 0xd3dc1fcf'u32,
      0xa1a02181'u32, 0x30303000'u32, 0x33343707'u32, 0xa2ac2e8e'u32, 0x32343606'u32, 0x11141505'u32, 0x22202202'u32, 0x30383808'u32,
      0xf0f434c4'u32, 0xa3a42787'u32, 0x41440545'u32, 0x404c0c4c'u32, 0x81800181'u32, 0xe1e829c9'u32, 0x80840484'u32, 0x93941787'u32,
      0x31343505'u32, 0xc3c80bcb'u32, 0xc2cc0ece'u32, 0x303c3c0c'u32, 0x71703141'u32, 0x11101101'u32, 0xc3c407c7'u32, 0x81880989'u32,
      0x71743545'u32, 0xf3f83bcb'u32, 0xd2d81aca'u32, 0xf0f838c8'u32, 0x90941484'u32, 0x51581949'u32, 0x82800282'u32, 0xc0c404c4'u32,
      0xf3fc3fcf'u32, 0x41480949'u32, 0x31383909'u32, 0x63642747'u32, 0xc0c000c0'u32, 0xc3cc0fcf'u32, 0xd3d417c7'u32, 0xb0b83888'u32,
      0x030c0f0f'u32, 0x828c0e8e'u32, 0x42400242'u32, 0x23202303'u32, 0x91901181'u32, 0x606c2c4c'u32, 0xd3d81bcb'u32, 0xa0a42484'u32,
      0x30343404'u32, 0xf1f031c1'u32, 0x40480848'u32, 0xc2c002c2'u32, 0x636c2f4f'u32, 0x313c3d0d'u32, 0x212c2d0d'u32, 0x40400040'u32,
      0xb2bc3e8e'u32, 0x323c3e0e'u32, 0xb0bc3c8c'u32, 0xc1c001c1'u32, 0xa2a82a8a'u32, 0xb2b83a8a'u32, 0x424c0e4e'u32, 0x51541545'u32,
      0x33383b0b'u32, 0xd0dc1ccc'u32, 0x60682848'u32, 0x737c3f4f'u32, 0x909c1c8c'u32, 0xd0d818c8'u32, 0x42480a4a'u32, 0x52541646'u32,
      0x73743747'u32, 0xa0a02080'u32, 0xe1ec2dcd'u32, 0x42440646'u32, 0xb1b43585'u32, 0x23282b0b'u32, 0x61642545'u32, 0xf2f83aca'u32,
      0xe3e023c3'u32, 0xb1b83989'u32, 0xb1b03181'u32, 0x939c1f8f'u32, 0x525c1e4e'u32, 0xf1f839c9'u32, 0xe2e426c6'u32, 0xb2b03282'u32,
      0x31303101'u32, 0xe2e82aca'u32, 0x616c2d4d'u32, 0x535c1f4f'u32, 0xe0e424c4'u32, 0xf0f030c0'u32, 0xc1cc0dcd'u32, 0x80880888'u32,
      0x12141606'u32, 0x32383a0a'u32, 0x50581848'u32, 0xd0d414c4'u32, 0x62602242'u32, 0x21282909'u32, 0x03040707'u32, 0x33303303'u32,
      0xe0e828c8'u32, 0x13181b0b'u32, 0x01040505'u32, 0x71783949'u32, 0x90901080'u32, 0x62682a4a'u32, 0x22282a0a'u32, 0x92981a8a'u32
    ],
    [
      0x08303838'u32, 0xc8e0e828'u32, 0x0d212c2d'u32, 0x86a2a426'u32, 0xcfc3cc0f'u32, 0xced2dc1e'u32, 0x83b3b033'u32, 0x88b0b838'u32,
      0x8fa3ac2f'u32, 0x40606020'u32, 0x45515415'u32, 0xc7c3c407'u32, 0x44404404'u32, 0x4f636c2f'u32, 0x4b63682b'u32, 0x4b53581b'u32,
      0xc3c3c003'u32, 0x42626022'u32, 0x03333033'u32, 0x85b1b435'u32, 0x09212829'u32, 0x80a0a020'u32, 0xc2e2e022'u32, 0x87a3a427'u32,
      0xc3d3d013'u32, 0x81919011'u32, 0x01111011'u32, 0x06020406'u32, 0x0c101c1c'u32, 0x8cb0bc3c'u32, 0x06323436'u32, 0x4b43480b'u32,
      0xcfe3ec2f'u32, 0x88808808'u32, 0x4c606c2c'u32, 0x88a0a828'u32, 0x07131417'u32, 0xc4c0c404'u32, 0x06121416'u32, 0xc4f0f434'u32,
      0xc2c2c002'u32, 0x45414405'u32, 0xc1e1e021'u32, 0xc6d2d416'u32, 0x0f333c3f'u32, 0x0d313c3d'u32, 0x8e828c0e'u32, 0x88909818'u32,
      0x08202828'u32, 0x4e424c0e'u32, 0xc6f2f436'u32, 0x0e323c3e'u32, 0x85a1a425'u32, 0xc9f1f839'u32, 0x0d010c0d'u32, 0xcfd3dc1f'u32,
      0xc8d0d818'u32, 0x0b23282b'u32, 0x46626426'u32, 0x4a72783a'u32, 0x07232427'u32, 0x0f232c2f'u32, 0xc1f1f031'u32, 0x42727032'u32,
      0x42424002'u32, 0xc4d0d414'u32, 0x41414001'u32, 0xc0c0c000'u32, 0x43737033'u32, 0x47636427'u32, 0x8ca0ac2c'u32, 0x8b83880b'u32,
      0xc7f3f437'u32, 0x8da1ac2d'u32, 0x80808000'u32, 0x0f131c1f'u32, 0xcac2c80a'u32, 0x0c202c2c'u32, 0x8aa2a82a'u32, 0x04303434'u32,
      0xc2d2d012'u32, 0x0b03080b'u32, 0xcee2ec2e'u32, 0xc9e1e829'u32, 0x4d515c1d'u32, 0x84909414'u32, 0x08101818'u32, 0xc8f0f838'u32,
      0x47535417'u32, 0x8ea2ac2e'u32, 0x08000808'u32, 0xc5c1c405'u32, 0x03131013'u32, 0xcdc1cc0d'u32, 0x86828406'u32, 0x89b1b839'u32,
      0xcff3fc3f'u32, 0x4d717c3d'u32, 0xc1c1c001'u32, 0x01313031'u32, 0xc5f1f435'u32, 0x8a82880a'u32, 0x4a62682a'u32, 0x81b1b031'u32,
      0xc1d1d011'u32, 0x00202020'u32, 0xc7d3d417'u32, 0x02020002'u32, 0x02222022'u32, 0x04000404'u32, 0x48606828'u32, 0x41717031'u32,
      0x07030407'u32, 0xcbd3d81b'u32, 0x8d919c1d'u32, 0x89919819'u32, 0x41616021'u32, 0x8eb2bc3e'u32, 0xc6e2e426'u32, 0x49515819'u32,
      0xcdd1dc1d'u32, 0x41515011'u32, 0x80909010'u32, 0xccd0dc1c'u32, 0x8a92981a'u32, 0x83a3a023'u32, 0x8ba3a82b'u32, 0xc0d0d010'u32,
      0x81818001'u32, 0x0f030c0f'u32, 0x47434407'u32, 0x0a12181a'u32, 0xc3e3e023'u32, 0xcce0ec2c'u32, 0x8d818c0d'u32, 0x8fb3bc3f'u32,
      0x86929416'u32, 0x4b73783b'u32, 0x4c505c1c'u32, 0x82a2a022'u32, 0x81a1a021'u32, 0x43636023'u32, 0x03232023'u32, 0x4d414c0d'u32,
      0xc8c0c808'u32, 0x8e929c1e'u32, 0x8c909c1c'u32, 0x0a32383a'u32, 0x0c000c0c'u32, 0x0e222c2e'u32, 0x8ab2b83a'u32, 0x4e626c2e'u32,
      0x8f939c1f'u32, 0x4a52581a'u32, 0xc2f2f032'u32, 0x82929012'u32, 0xc3f3f033'u32, 0x49414809'u32, 0x48707838'u32, 0xccc0cc0c'u32,
      0x05111415'u32, 0xcbf3f83b'u32, 0x40707030'u32, 0x45717435'u32, 0x4f737c3f'u32, 0x05313435'u32, 0x00101010'u32, 0x03030003'u32,
      0x44606424'u32, 0x4d616c2d'u32, 0xc6c2c406'u32, 0x44707434'u32, 0xc5d1d415'u32, 0x84b0b434'u32, 0xcae2e82a'u32, 0x09010809'u32,
      0x46727436'u32, 0x09111819'u32, 0xcef2fc3e'u32, 0x40404000'u32, 0x02121012'u32, 0xc0e0e020'u32, 0x8db1bc3d'u32, 0x05010405'u32,
      0xcaf2f83a'u32, 0x01010001'u32, 0xc0f0f030'u32, 0x0a22282a'u32, 0x4e525c1e'u32, 0x89a1a829'u32, 0x46525416'u32, 0x43434003'u32,
      0x85818405'u32, 0x04101414'u32, 0x89818809'u32, 0x8b93981b'u32, 0x80b0b030'u32, 0xc5e1e425'u32, 0x48404808'u32, 0x49717839'u32,
      0x87939417'u32, 0xccf0fc3c'u32, 0x0e121c1e'u32, 0x82828002'u32, 0x01212021'u32, 0x8c808c0c'u32, 0x0b13181b'u32, 0x4f535c1f'u32,
      0x47737437'u32, 0x44505414'u32, 0x82b2b032'u32, 0x0d111c1d'u32, 0x05212425'u32, 0x4f434c0f'u32, 0x00000000'u32, 0x46424406'u32,
      0xcde1ec2d'u32, 0x48505818'u32, 0x42525012'u32, 0xcbe3e82b'u32, 0x4e727c3e'u32, 0xcad2d81a'u32, 0xc9c1c809'u32, 0xcdf1fc3d'u32,
      0x00303030'u32, 0x85919415'u32, 0x45616425'u32, 0x0c303c3c'u32, 0x86b2b436'u32, 0xc4e0e424'u32, 0x8bb3b83b'u32, 0x4c707c3c'u32,
      0x0e020c0e'u32, 0x40505010'u32, 0x09313839'u32, 0x06222426'u32, 0x02323032'u32, 0x84808404'u32, 0x49616829'u32, 0x83939013'u32,
      0x07333437'u32, 0xc7e3e427'u32, 0x04202424'u32, 0x84a0a424'u32, 0xcbc3c80b'u32, 0x43535013'u32, 0x0a02080a'u32, 0x87838407'u32,
      0xc9d1d819'u32, 0x4c404c0c'u32, 0x83838003'u32, 0x8f838c0f'u32, 0xcec2cc0e'u32, 0x0b33383b'u32, 0x4a42480a'u32, 0x87b3b437'u32
    ]
  ]
  SBox: array[2, array[256, uint8]] = [
    [
      0xA9'u8, 0x85'u8, 0xD6'u8, 0xD3'u8, 0x54'u8, 0x1D'u8, 0xAC'u8, 0x25'u8,
      0x5D'u8, 0x43'u8, 0x18'u8, 0x1E'u8, 0x51'u8, 0xFC'u8, 0xCA'u8, 0x63'u8,
      0x28'u8, 0x44'u8, 0x20'u8, 0x9D'u8, 0xE0'u8, 0xE2'u8, 0xC8'u8, 0x17'u8,
      0xA5'u8, 0x8F'u8, 0x03'u8, 0x7B'u8, 0xBB'u8, 0x13'u8, 0xD2'u8, 0xEE'u8,
      0x70'u8, 0x8C'u8, 0x3F'u8, 0xA8'u8, 0x32'u8, 0xDD'u8, 0xF6'u8, 0x74'u8,
      0xEC'u8, 0x95'u8, 0x0B'u8, 0x57'u8, 0x5C'u8, 0x5B'u8, 0xBD'u8, 0x01'u8,
      0x24'u8, 0x1C'u8, 0x73'u8, 0x98'u8, 0x10'u8, 0xCC'u8, 0xF2'u8, 0xD9'u8,
      0x2C'u8, 0xE7'u8, 0x72'u8, 0x83'u8, 0x9B'u8, 0xD1'u8, 0x86'u8, 0xC9'u8,
      0x60'u8, 0x50'u8, 0xA3'u8, 0xEB'u8, 0x0D'u8, 0xB6'u8, 0x9E'u8, 0x4F'u8,
      0xB7'u8, 0x5A'u8, 0xC6'u8, 0x78'u8, 0xA6'u8, 0x12'u8, 0xAF'u8, 0xD5'u8,
      0x61'u8, 0xC3'u8, 0xB4'u8, 0x41'u8, 0x52'u8, 0x7D'u8, 0x8D'u8, 0x08'u8,
      0x1F'u8, 0x99'u8, 0x00'u8, 0x19'u8, 0x04'u8, 0x53'u8, 0xF7'u8, 0xE1'u8,
      0xFD'u8, 0x76'u8, 0x2F'u8, 0x27'u8, 0xB0'u8, 0x8B'u8, 0x0E'u8, 0xAB'u8,
      0xA2'u8, 0x6E'u8, 0x93'u8, 0x4D'u8, 0x69'u8, 0x7C'u8, 0x09'u8, 0x0A'u8,
      0xBF'u8, 0xEF'u8, 0xF3'u8, 0xC5'u8, 0x87'u8, 0x14'u8, 0xFE'u8, 0x64'u8,
      0xDE'u8, 0x2E'u8, 0x4B'u8, 0x1A'u8, 0x06'u8, 0x21'u8, 0x6B'u8, 0x66'u8,
      0x02'u8, 0xF5'u8, 0x92'u8, 0x8A'u8, 0x0C'u8, 0xB3'u8, 0x7E'u8, 0xD0'u8,
      0x7A'u8, 0x47'u8, 0x96'u8, 0xE5'u8, 0x26'u8, 0x80'u8, 0xAD'u8, 0xDF'u8,
      0xA1'u8, 0x30'u8, 0x37'u8, 0xAE'u8, 0x36'u8, 0x15'u8, 0x22'u8, 0x38'u8,
      0xF4'u8, 0xA7'u8, 0x45'u8, 0x4C'u8, 0x81'u8, 0xE9'u8, 0x84'u8, 0x97'u8,
      0x35'u8, 0xCB'u8, 0xCE'u8, 0x3C'u8, 0x71'u8, 0x11'u8, 0xC7'u8, 0x89'u8,
      0x75'u8, 0xFB'u8, 0xDA'u8, 0xF8'u8, 0x94'u8, 0x59'u8, 0x82'u8, 0xC4'u8,
      0xFF'u8, 0x49'u8, 0x39'u8, 0x67'u8, 0xC0'u8, 0xCF'u8, 0xD7'u8, 0xB8'u8,
      0x0F'u8, 0x8E'u8, 0x42'u8, 0x23'u8, 0x91'u8, 0x6C'u8, 0xDB'u8, 0xA4'u8,
      0x34'u8, 0xF1'u8, 0x48'u8, 0xC2'u8, 0x6F'u8, 0x3D'u8, 0x2D'u8, 0x40'u8,
      0xBE'u8, 0x3E'u8, 0xBC'u8, 0xC1'u8, 0xAA'u8, 0xBA'u8, 0x4E'u8, 0x55'u8,
      0x3B'u8, 0xDC'u8, 0x68'u8, 0x7F'u8, 0x9C'u8, 0xD8'u8, 0x4A'u8, 0x56'u8,
      0x77'u8, 0xA0'u8, 0xED'u8, 0x46'u8, 0xB5'u8, 0x2B'u8, 0x65'u8, 0xFA'u8,
      0xE3'u8, 0xB9'u8, 0xB1'u8, 0x9F'u8, 0x5E'u8, 0xF9'u8, 0xE6'u8, 0xB2'u8,
      0x31'u8, 0xEA'u8, 0x6D'u8, 0x5F'u8, 0xE4'u8, 0xF0'u8, 0xCD'u8, 0x88'u8,
      0x16'u8, 0x3A'u8, 0x58'u8, 0xD4'u8, 0x62'u8, 0x29'u8, 0x07'u8, 0x33'u8,
      0xE8'u8, 0x1B'u8, 0x05'u8, 0x79'u8, 0x90'u8, 0x6A'u8, 0x2A'u8, 0x9A'u8,
    ],
    [
      0x38'u8, 0xE8'u8, 0x2D'u8, 0xA6'u8, 0xCF'u8, 0xDE'u8, 0xB3'u8, 0xB8'u8,
      0xAF'u8, 0x60'u8, 0x55'u8, 0xC7'u8, 0x44'u8, 0x6F'u8, 0x6B'u8, 0x5B'u8,
      0xC3'u8, 0x62'u8, 0x33'u8, 0xB5'u8, 0x29'u8, 0xA0'u8, 0xE2'u8, 0xA7'u8,
      0xD3'u8, 0x91'u8, 0x11'u8, 0x06'u8, 0x1C'u8, 0xBC'u8, 0x36'u8, 0x4B'u8,
      0xEF'u8, 0x88'u8, 0x6C'u8, 0xA8'u8, 0x17'u8, 0xC4'u8, 0x16'u8, 0xF4'u8,
      0xC2'u8, 0x45'u8, 0xE1'u8, 0xD6'u8, 0x3F'u8, 0x3D'u8, 0x8E'u8, 0x98'u8,
      0x28'u8, 0x4E'u8, 0xF6'u8, 0x3E'u8, 0xA5'u8, 0xF9'u8, 0x0D'u8, 0xDF'u8,
      0xD8'u8, 0x2B'u8, 0x66'u8, 0x7A'u8, 0x27'u8, 0x2F'u8, 0xF1'u8, 0x72'u8,
      0x42'u8, 0xD4'u8, 0x41'u8, 0xC0'u8, 0x73'u8, 0x67'u8, 0xAC'u8, 0x8B'u8,
      0xF7'u8, 0xAD'u8, 0x80'u8, 0x1F'u8, 0xCA'u8, 0x2C'u8, 0xAA'u8, 0x34'u8,
      0xD2'u8, 0x0B'u8, 0xEE'u8, 0xE9'u8, 0x5D'u8, 0x94'u8, 0x18'u8, 0xF8'u8,
      0x57'u8, 0xAE'u8, 0x08'u8, 0xC5'u8, 0x13'u8, 0xCD'u8, 0x86'u8, 0xB9'u8,
      0xFF'u8, 0x7D'u8, 0xC1'u8, 0x31'u8, 0xF5'u8, 0x8A'u8, 0x6A'u8, 0xB1'u8,
      0xD1'u8, 0x20'u8, 0xD7'u8, 0x02'u8, 0x22'u8, 0x04'u8, 0x68'u8, 0x71'u8,
      0x07'u8, 0xDB'u8, 0x9D'u8, 0x99'u8, 0x61'u8, 0xBE'u8, 0xE6'u8, 0x59'u8,
      0xDD'u8, 0x51'u8, 0x90'u8, 0xDC'u8, 0x9A'u8, 0xA3'u8, 0xAB'u8, 0xD0'u8,
      0x81'u8, 0x0F'u8, 0x47'u8, 0x1A'u8, 0xE3'u8, 0xEC'u8, 0x8D'u8, 0xBF'u8,
      0x96'u8, 0x7B'u8, 0x5C'u8, 0xA2'u8, 0xA1'u8, 0x63'u8, 0x23'u8, 0x4D'u8,
      0xC8'u8, 0x9E'u8, 0x9C'u8, 0x3A'u8, 0x0C'u8, 0x2E'u8, 0xBA'u8, 0x6E'u8,
      0x9F'u8, 0x5A'u8, 0xF2'u8, 0x92'u8, 0xF3'u8, 0x49'u8, 0x78'u8, 0xCC'u8,
      0x15'u8, 0xFB'u8, 0x70'u8, 0x75'u8, 0x7F'u8, 0x35'u8, 0x10'u8, 0x03'u8,
      0x64'u8, 0x6D'u8, 0xC6'u8, 0x74'u8, 0xD5'u8, 0xB4'u8, 0xEA'u8, 0x09'u8,
      0x76'u8, 0x19'u8, 0xFE'u8, 0x40'u8, 0x12'u8, 0xE0'u8, 0xBD'u8, 0x05'u8,
      0xFA'u8, 0x01'u8, 0xF0'u8, 0x2A'u8, 0x5E'u8, 0xA9'u8, 0x56'u8, 0x43'u8,
      0x85'u8, 0x14'u8, 0x89'u8, 0x9B'u8, 0xB0'u8, 0xE5'u8, 0x48'u8, 0x79'u8,
      0x97'u8, 0xFC'u8, 0x1E'u8, 0x82'u8, 0x21'u8, 0x8C'u8, 0x1B'u8, 0x5F'u8,
      0x77'u8, 0x54'u8, 0xB2'u8, 0x1D'u8, 0x25'u8, 0x4F'u8, 0x00'u8, 0x46'u8,
      0xED'u8, 0x58'u8, 0x52'u8, 0xEB'u8, 0x7E'u8, 0xDA'u8, 0xC9'u8, 0xFD'u8,
      0x30'u8, 0x95'u8, 0x65'u8, 0x3C'u8, 0xB6'u8, 0xE4'u8, 0xBB'u8, 0x7C'u8,
      0x0E'u8, 0x50'u8, 0x39'u8, 0x26'u8, 0x32'u8, 0x84'u8, 0x69'u8, 0x93'u8,
      0x37'u8, 0xE7'u8, 0x24'u8, 0xA4'u8, 0xCB'u8, 0x53'u8, 0x0A'u8, 0x87'u8,
      0xD9'u8, 0x4C'u8, 0x83'u8, 0x8F'u8, 0xCE'u8, 0x3B'u8, 0x4A'u8, 0xB7'u8
    ]
  ]
  # declare information constants : block size, key size, round number
  SEED_BLOCK_SIZE*: int = 16
  SEED_KEY_SIZE*: int = 16
  ROUND_NUMBER*: int = 16

type
  # declare seed context
  SEEDCtx* = object
    roundKey: array[32, uint32]

template G(x: uint32): uint32 =
  Table[0][uint8((x shr  0) and 0xFF'u32)] xor
  Table[1][uint8((x shr  8) and 0xFF'u32)] xor
  Table[2][uint8((x shr 16) and 0xFF'u32)] xor
  Table[3][uint8((x shr 24) and 0xFF'u32)]

# seed init core
template seedInitC(ctx: var SEEDCtx, key: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # declare temporary variables
  var a, b, c, d, temp0, temp1: uint32
  # decode key to temp variables
  fromBytesBE(key.toSliceArray(0, 3), a)
  fromBytesBE(key.toSliceArray(4, 7), b)
  fromBytesBE(key.toSliceArray(8, 11), c)
  fromBytesBE(key.toSliceArray(12, 15), d)

  temp0 = (a + c - KC[0]) and 0xFFFFFFFF'u32
  temp1 = (b - d + KC[0]) and 0xFFFFFFFF'u32
  ctx.roundKey[0] = G(temp0)
  ctx.roundKey[1] = G(temp1)

  template scheduleRound(keyIndex, kcIndex: static int, rotate: static bool): void =
    when rotate:
      temp0 = a
      a = ((a shr 8) xor (b shl 24)) and 0xFFFFFFFF'u32
      b = ((b shr 8) xor (temp0 shl 24)) and 0xFFFFFFFF'u32
    else:
      temp0 = c
      c = ((c shl 8) xor (d shr 24)) and 0xFFFFFFFF'u32
      d = ((d shl 8) xor (temp0 shr 24)) and 0xFFFFFFFF'u32

    temp0 = a + c - KC[kcIndex]
    temp1 = b - d + KC[kcIndex]

    ctx.roundKey[keyIndex + 0] = G(temp0)
    ctx.roundKey[keyIndex + 1] = G(temp1)

  # key schedule round loop unroll
  scheduleRound(2, 1, true)
  scheduleRound(4, 2, false)
  scheduleRound(6, 3, true)
  scheduleRound(8, 4, false)
  scheduleRound(10, 5, true)
  scheduleRound(12, 6, false)
  scheduleRound(14, 7, true)
  scheduleRound(16, 8, false)
  scheduleRound(18, 9, true)
  scheduleRound(20, 10, false)
  scheduleRound(22, 11, true)
  scheduleRound(24, 12, false)
  scheduleRound(26, 13, true)
  scheduleRound(28, 14, false)
  scheduleRound(30, 15, true)

# seed encrypt core
template seedEncryptC(ctx: SEEDCtx, input, output: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # declare temporary variables
  var left0, left1, right0, right1, temp0, temp1: uint32
  # decode state to temp variables
  fromBytesBE(input.toSliceArray(0, 3), left0)
  fromBytesBE(input.toSliceArray(4, 7), left1)
  fromBytesBE(input.toSliceArray(8, 11), right0)
  fromBytesBE(input.toSliceArray(12, 15), right1)

  # round template
  template round(index: static int, a, b, c, d: var uint32): void =
    temp0 = c xor ctx.roundKey[index + 0]
    temp1 = d xor ctx.roundKey[index + 1]
    temp1 ^= temp0
    temp1 = G(temp1)
    temp0 = temp0 + temp1
    temp0 = G(temp0)
    temp1 = temp1 + temp0
    temp1 = G(temp1)
    temp0 = temp0 + temp1
    a ^= temp0
    b ^= temp1

  # round loop unroll
  round(0, left0, left1, right0, right1)
  round(2, right0, right1, left0, left1)
  round(4, left0, left1, right0, right1)
  round(6, right0, right1, left0, left1)
  round(8, left0, left1, right0, right1)
  round(10, right0, right1, left0, left1)
  round(12, left0, left1, right0, right1)
  round(14, right0, right1, left0, left1)
  round(16, left0, left1, right0, right1)
  round(18, right0, right1, left0, left1)
  round(20, left0, left1, right0, right1)
  round(22, right0, right1, left0, left1)
  round(24, left0, left1, right0, right1)
  round(26, right0, right1, left0, left1)
  round(28, left0, left1, right0, right1)
  round(30, right0, right1, left0, left1)

  # encode temp variables to state
  toBytesBE(right0, output.toSliceArray(0, 3))
  toBytesBE(right1, output.toSliceArray(4, 7))
  toBytesBE(left0, output.toSliceArray(8, 11))
  toBytesBE(left1, output.toSliceArray(12, 15))

# seed decrypt core
template seedDecryptC(ctx: SEEDCtx, input, output: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # declare temporary variables
  var left0, left1, right0, right1, temp0, temp1: uint32
  # decode state to temp variables
  fromBytesBE(input.toSliceArray(0, 3), left0)
  fromBytesBE(input.toSliceArray(4, 7), left1)
  fromBytesBE(input.toSliceArray(8, 11), right0)
  fromBytesBE(input.toSliceArray(12, 15), right1)

  # round template
  template round(index: static int, a, b, c, d: var uint32): void =
    temp0 = c xor ctx.roundKey[index + 0]
    temp1 = d xor ctx.roundKey[index + 1]
    temp1 ^= temp0
    temp1 = G(temp1)
    temp0 = temp0 + temp1
    temp0 = G(temp0)
    temp1 = temp1 + temp0
    temp1 = G(temp1)
    temp0 = temp0 + temp1
    a ^= temp0
    b ^= temp1

  # round loop unroll
  round(30, left0, left1, right0, right1)
  round(28, right0, right1, left0, left1)
  round(26, left0, left1, right0, right1)
  round(24, right0, right1, left0, left1)
  round(22, left0, left1, right0, right1)
  round(20, right0, right1, left0, left1)
  round(18, left0, left1, right0, right1)
  round(16, right0, right1, left0, left1)
  round(14, left0, left1, right0, right1)
  round(12, right0, right1, left0, left1)
  round(10, left0, left1, right0, right1)
  round(8, right0, right1, left0, left1)
  round(6, left0, left1, right0, right1)
  round(4, right0, right1, left0, left1)
  round(2, left0, left1, right0, right1)
  round(0, right0, right1, left0, left1)

  # encode temp variables to state
  toBytesBE(right0, output.toSliceArray(0, 3))
  toBytesBE(right1, output.toSliceArray(4, 7))
  toBytesBE(left0, output.toSliceArray(8, 11))
  toBytesBE(left1, output.toSliceArray(12, 15))

# export wrappers
when defined(templateOpt):
  template seedInit*(ctx: var SEEDCtx, key: array[16, uint8]): void =
    seedInitC(ctx, key.toSliceArray(0, 15))
  template seedInit*(ctx: var SEEDCtx, key: openArray[uint8]): void =
    seedInitC(ctx, key.toSliceArray(0, 15))
  template seedInit*(ctx: var SEEDCtx, key: slicearray[16, uint8]): void =
    seedInitC(ctx, key)
  template seedInit*(ctx: ptr SEEDCtx, key: ptr array[16, uint8]): void =
    seedInitC(ctx[], key.toSliceArray(0, 15))

  template seedEncrypt*(ctx: SEEDCtx, input: array[16, uint8], output: var array[16, uint8]): void =
    seedEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template seedEncrypt*(ctx: SEEDCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    seedEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template seedEncrypt*(ctx: SEEDCtx, input, output: slicearray[16, uint8]): void =
    seedEncryptC(ctx, input, output)
  template seedEncrypt*(ctx: SEEDCtx, input, output: ptr array[16, uint8]): void =
    seedEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template seedDecrypt*(ctx: SEEDCtx, input: array[16, uint8], output: var array[16, uint8]): void =
    seedDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template seedDecrypt*(ctx: SEEDCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    seedDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template seedDecrypt*(ctx: SEEDCtx, input, output: slicearray[16, uint8]): void =
    seedDecryptC(ctx, input, output)
  template seedDecrypt*(ctx: SEEDCtx, input, output: ptr array[16, uint8]): void =
    seedDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
else:
  proc seedInit*(ctx: var SEEDCtx, key: array[16, uint8]): void =
    seedInitC(ctx, key.toSliceArray(0, 15))
  proc seedInit*(ctx: var SEEDCtx, key: openArray[uint8]): void =
    seedInitC(ctx, key.toSliceArray(0, 15))
  proc seedInit*(ctx: var SEEDCtx, key: slicearray[16, uint8]): void =
    seedInitC(ctx, key)
  proc seedInit*(ctx: ptr SEEDCtx, key: ptr array[16, uint8]): void =
    seedInitC(ctx[], key.toSliceArray(0, 15))

  proc seedEncrypt*(ctx: SEEDCtx, input: array[16, uint8], output: var array[16, uint8]): void =
    seedEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc seedEncrypt*(ctx: SEEDCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    seedEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc seedEncrypt*(ctx: SEEDCtx, input, output: slicearray[16, uint8]): void =
    seedEncryptC(ctx, input, output)
  proc seedEncrypt*(ctx: SEEDCtx, input, output: ptr array[16, uint8]): void =
    seedEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc seedDecrypt*(ctx: SEEDCtx, input: array[16, uint8], output: var array[16, uint8]): void =
    seedDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc seedDecrypt*(ctx: SEEDCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    seedDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc seedDecrypt*(ctx: SEEDCtx, input, output: slicearray[16, uint8]): void =
    seedDecryptC(ctx, input, output)
  proc seedDecrypt*(ctx: SEEDCtx, input, output: ptr array[16, uint8]): void =
    seedDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

