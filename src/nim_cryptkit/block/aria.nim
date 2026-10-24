import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import ../utils/biguintBE
import std/[monotimes, times]
import std/bitops
import strutils

const
  # declare S-Box 1/2/3/4
  SBox1: array[256, uint8] = [
    0x63'u8, 0x7c'u8, 0x77'u8, 0x7b'u8, 0xf2'u8, 0x6b'u8, 0x6f'u8, 0xc5'u8, 0x30'u8, 0x01'u8, 0x67'u8, 0x2b'u8, 0xfe'u8, 0xd7'u8, 0xab'u8, 0x76'u8,
    0xca'u8, 0x82'u8, 0xc9'u8, 0x7d'u8, 0xfa'u8, 0x59'u8, 0x47'u8, 0xf0'u8, 0xad'u8, 0xd4'u8, 0xa2'u8, 0xaf'u8, 0x9c'u8, 0xa4'u8, 0x72'u8, 0xc0'u8,
    0xb7'u8, 0xfd'u8, 0x93'u8, 0x26'u8, 0x36'u8, 0x3f'u8, 0xf7'u8, 0xcc'u8, 0x34'u8, 0xa5'u8, 0xe5'u8, 0xf1'u8, 0x71'u8, 0xd8'u8, 0x31'u8, 0x15'u8,
    0x04'u8, 0xc7'u8, 0x23'u8, 0xc3'u8, 0x18'u8, 0x96'u8, 0x05'u8, 0x9a'u8, 0x07'u8, 0x12'u8, 0x80'u8, 0xe2'u8, 0xeb'u8, 0x27'u8, 0xb2'u8, 0x75'u8,
    0x09'u8, 0x83'u8, 0x2c'u8, 0x1a'u8, 0x1b'u8, 0x6e'u8, 0x5a'u8, 0xa0'u8, 0x52'u8, 0x3b'u8, 0xd6'u8, 0xb3'u8, 0x29'u8, 0xe3'u8, 0x2f'u8, 0x84'u8,
    0x53'u8, 0xd1'u8, 0x00'u8, 0xed'u8, 0x20'u8, 0xfc'u8, 0xb1'u8, 0x5b'u8, 0x6a'u8, 0xcb'u8, 0xbe'u8, 0x39'u8, 0x4a'u8, 0x4c'u8, 0x58'u8, 0xcf'u8,
    0xd0'u8, 0xef'u8, 0xaa'u8, 0xfb'u8, 0x43'u8, 0x4d'u8, 0x33'u8, 0x85'u8, 0x45'u8, 0xf9'u8, 0x02'u8, 0x7f'u8, 0x50'u8, 0x3c'u8, 0x9f'u8, 0xa8'u8,
    0x51'u8, 0xa3'u8, 0x40'u8, 0x8f'u8, 0x92'u8, 0x9d'u8, 0x38'u8, 0xf5'u8, 0xbc'u8, 0xb6'u8, 0xda'u8, 0x21'u8, 0x10'u8, 0xff'u8, 0xf3'u8, 0xd2'u8,
    0xcd'u8, 0x0c'u8, 0x13'u8, 0xec'u8, 0x5f'u8, 0x97'u8, 0x44'u8, 0x17'u8, 0xc4'u8, 0xa7'u8, 0x7e'u8, 0x3d'u8, 0x64'u8, 0x5d'u8, 0x19'u8, 0x73'u8,
    0x60'u8, 0x81'u8, 0x4f'u8, 0xdc'u8, 0x22'u8, 0x2a'u8, 0x90'u8, 0x88'u8, 0x46'u8, 0xee'u8, 0xb8'u8, 0x14'u8, 0xde'u8, 0x5e'u8, 0x0b'u8, 0xdb'u8,
    0xe0'u8, 0x32'u8, 0x3a'u8, 0x0a'u8, 0x49'u8, 0x06'u8, 0x24'u8, 0x5c'u8, 0xc2'u8, 0xd3'u8, 0xac'u8, 0x62'u8, 0x91'u8, 0x95'u8, 0xe4'u8, 0x79'u8,
    0xe7'u8, 0xc8'u8, 0x37'u8, 0x6d'u8, 0x8d'u8, 0xd5'u8, 0x4e'u8, 0xa9'u8, 0x6c'u8, 0x56'u8, 0xf4'u8, 0xea'u8, 0x65'u8, 0x7a'u8, 0xae'u8, 0x08'u8,
    0xba'u8, 0x78'u8, 0x25'u8, 0x2e'u8, 0x1c'u8, 0xa6'u8, 0xb4'u8, 0xc6'u8, 0xe8'u8, 0xdd'u8, 0x74'u8, 0x1f'u8, 0x4b'u8, 0xbd'u8, 0x8b'u8, 0x8a'u8,
    0x70'u8, 0x3e'u8, 0xb5'u8, 0x66'u8, 0x48'u8, 0x03'u8, 0xf6'u8, 0x0e'u8, 0x61'u8, 0x35'u8, 0x57'u8, 0xb9'u8, 0x86'u8, 0xc1'u8, 0x1d'u8, 0x9e'u8,
    0xe1'u8, 0xf8'u8, 0x98'u8, 0x11'u8, 0x69'u8, 0xd9'u8, 0x8e'u8, 0x94'u8, 0x9b'u8, 0x1e'u8, 0x87'u8, 0xe9'u8, 0xce'u8, 0x55'u8, 0x28'u8, 0xdf'u8,
    0x8c'u8, 0xa1'u8, 0x89'u8, 0x0d'u8, 0xbf'u8, 0xe6'u8, 0x42'u8, 0x68'u8, 0x41'u8, 0x99'u8, 0x2d'u8, 0x0f'u8, 0xb0'u8, 0x54'u8, 0xbb'u8, 0x16'u8
  ]
  SBox2: array[256, uint8] = [
    0xe2'u8, 0x4e'u8, 0x54'u8, 0xfc'u8, 0x94'u8, 0xc2'u8, 0x4a'u8, 0xcc'u8, 0x62'u8, 0x0d'u8, 0x6a'u8, 0x46'u8, 0x3c'u8, 0x4d'u8, 0x8b'u8, 0xd1'u8,
    0x5e'u8, 0xfa'u8, 0x64'u8, 0xcb'u8, 0xb4'u8, 0x97'u8, 0xbe'u8, 0x2b'u8, 0xbc'u8, 0x77'u8, 0x2e'u8, 0x03'u8, 0xd3'u8, 0x19'u8, 0x59'u8, 0xc1'u8,
    0x1d'u8, 0x06'u8, 0x41'u8, 0x6b'u8, 0x55'u8, 0xf0'u8, 0x99'u8, 0x69'u8, 0xea'u8, 0x9c'u8, 0x18'u8, 0xae'u8, 0x63'u8, 0xdf'u8, 0xe7'u8, 0xbb'u8,
    0x00'u8, 0x73'u8, 0x66'u8, 0xfb'u8, 0x96'u8, 0x4c'u8, 0x85'u8, 0xe4'u8, 0x3a'u8, 0x09'u8, 0x45'u8, 0xaa'u8, 0x0f'u8, 0xee'u8, 0x10'u8, 0xeb'u8,
    0x2d'u8, 0x7f'u8, 0xf4'u8, 0x29'u8, 0xac'u8, 0xcf'u8, 0xad'u8, 0x91'u8, 0x8d'u8, 0x78'u8, 0xc8'u8, 0x95'u8, 0xf9'u8, 0x2f'u8, 0xce'u8, 0xcd'u8,
    0x08'u8, 0x7a'u8, 0x88'u8, 0x38'u8, 0x5c'u8, 0x83'u8, 0x2a'u8, 0x28'u8, 0x47'u8, 0xdb'u8, 0xb8'u8, 0xc7'u8, 0x93'u8, 0xa4'u8, 0x12'u8, 0x53'u8,
    0xff'u8, 0x87'u8, 0x0e'u8, 0x31'u8, 0x36'u8, 0x21'u8, 0x58'u8, 0x48'u8, 0x01'u8, 0x8e'u8, 0x37'u8, 0x74'u8, 0x32'u8, 0xca'u8, 0xe9'u8, 0xb1'u8,
    0xb7'u8, 0xab'u8, 0x0c'u8, 0xd7'u8, 0xc4'u8, 0x56'u8, 0x42'u8, 0x26'u8, 0x07'u8, 0x98'u8, 0x60'u8, 0xd9'u8, 0xb6'u8, 0xb9'u8, 0x11'u8, 0x40'u8,
    0xec'u8, 0x20'u8, 0x8c'u8, 0xbd'u8, 0xa0'u8, 0xc9'u8, 0x84'u8, 0x04'u8, 0x49'u8, 0x23'u8, 0xf1'u8, 0x4f'u8, 0x50'u8, 0x1f'u8, 0x13'u8, 0xdc'u8,
    0xd8'u8, 0xc0'u8, 0x9e'u8, 0x57'u8, 0xe3'u8, 0xc3'u8, 0x7b'u8, 0x65'u8, 0x3b'u8, 0x02'u8, 0x8f'u8, 0x3e'u8, 0xe8'u8, 0x25'u8, 0x92'u8, 0xe5'u8,
    0x15'u8, 0xdd'u8, 0xfd'u8, 0x17'u8, 0xa9'u8, 0xbf'u8, 0xd4'u8, 0x9a'u8, 0x7e'u8, 0xc5'u8, 0x39'u8, 0x67'u8, 0xfe'u8, 0x76'u8, 0x9d'u8, 0x43'u8,
    0xa7'u8, 0xe1'u8, 0xd0'u8, 0xf5'u8, 0x68'u8, 0xf2'u8, 0x1b'u8, 0x34'u8, 0x70'u8, 0x05'u8, 0xa3'u8, 0x8a'u8, 0xd5'u8, 0x79'u8, 0x86'u8, 0xa8'u8,
    0x30'u8, 0xc6'u8, 0x51'u8, 0x4b'u8, 0x1e'u8, 0xa6'u8, 0x27'u8, 0xf6'u8, 0x35'u8, 0xd2'u8, 0x6e'u8, 0x24'u8, 0x16'u8, 0x82'u8, 0x5f'u8, 0xda'u8,
    0xe6'u8, 0x75'u8, 0xa2'u8, 0xef'u8, 0x2c'u8, 0xb2'u8, 0x1c'u8, 0x9f'u8, 0x5d'u8, 0x6f'u8, 0x80'u8, 0x0a'u8, 0x72'u8, 0x44'u8, 0x9b'u8, 0x6c'u8,
    0x90'u8, 0x0b'u8, 0x5b'u8, 0x33'u8, 0x7d'u8, 0x5a'u8, 0x52'u8, 0xf3'u8, 0x61'u8, 0xa1'u8, 0xf7'u8, 0xb0'u8, 0xd6'u8, 0x3f'u8, 0x7c'u8, 0x6d'u8,
    0xed'u8, 0x14'u8, 0xe0'u8, 0xa5'u8, 0x3d'u8, 0x22'u8, 0xb3'u8, 0xf8'u8, 0x89'u8, 0xde'u8, 0x71'u8, 0x1a'u8, 0xaf'u8, 0xba'u8, 0xb5'u8, 0x81'u8
  ]
  SBox3: array[256, uint8] = [
    0x52'u8, 0x09'u8, 0x6a'u8, 0xd5'u8, 0x30'u8, 0x36'u8, 0xa5'u8, 0x38'u8, 0xbf'u8, 0x40'u8, 0xa3'u8, 0x9e'u8, 0x81'u8, 0xf3'u8, 0xd7'u8, 0xfb'u8,
    0x7c'u8, 0xe3'u8, 0x39'u8, 0x82'u8, 0x9b'u8, 0x2f'u8, 0xff'u8, 0x87'u8, 0x34'u8, 0x8e'u8, 0x43'u8, 0x44'u8, 0xc4'u8, 0xde'u8, 0xe9'u8, 0xcb'u8,
    0x54'u8, 0x7b'u8, 0x94'u8, 0x32'u8, 0xa6'u8, 0xc2'u8, 0x23'u8, 0x3d'u8, 0xee'u8, 0x4c'u8, 0x95'u8, 0x0b'u8, 0x42'u8, 0xfa'u8, 0xc3'u8, 0x4e'u8,
    0x08'u8, 0x2e'u8, 0xa1'u8, 0x66'u8, 0x28'u8, 0xd9'u8, 0x24'u8, 0xb2'u8, 0x76'u8, 0x5b'u8, 0xa2'u8, 0x49'u8, 0x6d'u8, 0x8b'u8, 0xd1'u8, 0x25'u8,
    0x72'u8, 0xf8'u8, 0xf6'u8, 0x64'u8, 0x86'u8, 0x68'u8, 0x98'u8, 0x16'u8, 0xd4'u8, 0xa4'u8, 0x5c'u8, 0xcc'u8, 0x5d'u8, 0x65'u8, 0xb6'u8, 0x92'u8,
    0x6c'u8, 0x70'u8, 0x48'u8, 0x50'u8, 0xfd'u8, 0xed'u8, 0xb9'u8, 0xda'u8, 0x5e'u8, 0x15'u8, 0x46'u8, 0x57'u8, 0xa7'u8, 0x8d'u8, 0x9d'u8, 0x84'u8,
    0x90'u8, 0xd8'u8, 0xab'u8, 0x00'u8, 0x8c'u8, 0xbc'u8, 0xd3'u8, 0x0a'u8, 0xf7'u8, 0xe4'u8, 0x58'u8, 0x05'u8, 0xb8'u8, 0xb3'u8, 0x45'u8, 0x06'u8,
    0xd0'u8, 0x2c'u8, 0x1e'u8, 0x8f'u8, 0xca'u8, 0x3f'u8, 0x0f'u8, 0x02'u8, 0xc1'u8, 0xaf'u8, 0xbd'u8, 0x03'u8, 0x01'u8, 0x13'u8, 0x8a'u8, 0x6b'u8,
    0x3a'u8, 0x91'u8, 0x11'u8, 0x41'u8, 0x4f'u8, 0x67'u8, 0xdc'u8, 0xea'u8, 0x97'u8, 0xf2'u8, 0xcf'u8, 0xce'u8, 0xf0'u8, 0xb4'u8, 0xe6'u8, 0x73'u8,
    0x96'u8, 0xac'u8, 0x74'u8, 0x22'u8, 0xe7'u8, 0xad'u8, 0x35'u8, 0x85'u8, 0xe2'u8, 0xf9'u8, 0x37'u8, 0xe8'u8, 0x1c'u8, 0x75'u8, 0xdf'u8, 0x6e'u8,
    0x47'u8, 0xf1'u8, 0x1a'u8, 0x71'u8, 0x1d'u8, 0x29'u8, 0xc5'u8, 0x89'u8, 0x6f'u8, 0xb7'u8, 0x62'u8, 0x0e'u8, 0xaa'u8, 0x18'u8, 0xbe'u8, 0x1b'u8,
    0xfc'u8, 0x56'u8, 0x3e'u8, 0x4b'u8, 0xc6'u8, 0xd2'u8, 0x79'u8, 0x20'u8, 0x9a'u8, 0xdb'u8, 0xc0'u8, 0xfe'u8, 0x78'u8, 0xcd'u8, 0x5a'u8, 0xf4'u8,
    0x1f'u8, 0xdd'u8, 0xa8'u8, 0x33'u8, 0x88'u8, 0x07'u8, 0xc7'u8, 0x31'u8, 0xb1'u8, 0x12'u8, 0x10'u8, 0x59'u8, 0x27'u8, 0x80'u8, 0xec'u8, 0x5f'u8,
    0x60'u8, 0x51'u8, 0x7f'u8, 0xa9'u8, 0x19'u8, 0xb5'u8, 0x4a'u8, 0x0d'u8, 0x2d'u8, 0xe5'u8, 0x7a'u8, 0x9f'u8, 0x93'u8, 0xc9'u8, 0x9c'u8, 0xef'u8,
    0xa0'u8, 0xe0'u8, 0x3b'u8, 0x4d'u8, 0xae'u8, 0x2a'u8, 0xf5'u8, 0xb0'u8, 0xc8'u8, 0xeb'u8, 0xbb'u8, 0x3c'u8, 0x83'u8, 0x53'u8, 0x99'u8, 0x61'u8,
    0x17'u8, 0x2b'u8, 0x04'u8, 0x7e'u8, 0xba'u8, 0x77'u8, 0xd6'u8, 0x26'u8, 0xe1'u8, 0x69'u8, 0x14'u8, 0x63'u8, 0x55'u8, 0x21'u8, 0x0c'u8, 0x7d'u8
  ]
  SBox4: array[256, uint8] = [
    0x30'u8, 0x68'u8, 0x99'u8, 0x1b'u8, 0x87'u8, 0xb9'u8, 0x21'u8, 0x78'u8, 0x50'u8, 0x39'u8, 0xdb'u8, 0xe1'u8, 0x72'u8, 0x09'u8, 0x62'u8, 0x3c'u8,
    0x3e'u8, 0x7e'u8, 0x5e'u8, 0x8e'u8, 0xf1'u8, 0xa0'u8, 0xcc'u8, 0xa3'u8, 0x2a'u8, 0x1d'u8, 0xfb'u8, 0xb6'u8, 0xd6'u8, 0x20'u8, 0xc4'u8, 0x8d'u8,
    0x81'u8, 0x65'u8, 0xf5'u8, 0x89'u8, 0xcb'u8, 0x9d'u8, 0x77'u8, 0xc6'u8, 0x57'u8, 0x43'u8, 0x56'u8, 0x17'u8, 0xd4'u8, 0x40'u8, 0x1a'u8, 0x4d'u8,
    0xc0'u8, 0x63'u8, 0x6c'u8, 0xe3'u8, 0xb7'u8, 0xc8'u8, 0x64'u8, 0x6a'u8, 0x53'u8, 0xaa'u8, 0x38'u8, 0x98'u8, 0x0c'u8, 0xf4'u8, 0x9b'u8, 0xed'u8,
    0x7f'u8, 0x22'u8, 0x76'u8, 0xaf'u8, 0xdd'u8, 0x3a'u8, 0x0b'u8, 0x58'u8, 0x67'u8, 0x88'u8, 0x06'u8, 0xc3'u8, 0x35'u8, 0x0d'u8, 0x01'u8, 0x8b'u8,
    0x8c'u8, 0xc2'u8, 0xe6'u8, 0x5f'u8, 0x02'u8, 0x24'u8, 0x75'u8, 0x93'u8, 0x66'u8, 0x1e'u8, 0xe5'u8, 0xe2'u8, 0x54'u8, 0xd8'u8, 0x10'u8, 0xce'u8,
    0x7a'u8, 0xe8'u8, 0x08'u8, 0x2c'u8, 0x12'u8, 0x97'u8, 0x32'u8, 0xab'u8, 0xb4'u8, 0x27'u8, 0x0a'u8, 0x23'u8, 0xdf'u8, 0xef'u8, 0xca'u8, 0xd9'u8,
    0xb8'u8, 0xfa'u8, 0xdc'u8, 0x31'u8, 0x6b'u8, 0xd1'u8, 0xad'u8, 0x19'u8, 0x49'u8, 0xbd'u8, 0x51'u8, 0x96'u8, 0xee'u8, 0xe4'u8, 0xa8'u8, 0x41'u8,
    0xda'u8, 0xff'u8, 0xcd'u8, 0x55'u8, 0x86'u8, 0x36'u8, 0xbe'u8, 0x61'u8, 0x52'u8, 0xf8'u8, 0xbb'u8, 0x0e'u8, 0x82'u8, 0x48'u8, 0x69'u8, 0x9a'u8,
    0xe0'u8, 0x47'u8, 0x9e'u8, 0x5c'u8, 0x04'u8, 0x4b'u8, 0x34'u8, 0x15'u8, 0x79'u8, 0x26'u8, 0xa7'u8, 0xde'u8, 0x29'u8, 0xae'u8, 0x92'u8, 0xd7'u8,
    0x84'u8, 0xe9'u8, 0xd2'u8, 0xba'u8, 0x5d'u8, 0xf3'u8, 0xc5'u8, 0xb0'u8, 0xbf'u8, 0xa4'u8, 0x3b'u8, 0x71'u8, 0x44'u8, 0x46'u8, 0x2b'u8, 0xfc'u8,
    0xeb'u8, 0x6f'u8, 0xd5'u8, 0xf6'u8, 0x14'u8, 0xfe'u8, 0x7c'u8, 0x70'u8, 0x5a'u8, 0x7d'u8, 0xfd'u8, 0x2f'u8, 0x18'u8, 0x83'u8, 0x16'u8, 0xa5'u8,
    0x91'u8, 0x1f'u8, 0x05'u8, 0x95'u8, 0x74'u8, 0xa9'u8, 0xc1'u8, 0x5b'u8, 0x4a'u8, 0x85'u8, 0x6d'u8, 0x13'u8, 0x07'u8, 0x4f'u8, 0x4e'u8, 0x45'u8,
    0xb2'u8, 0x0f'u8, 0xc9'u8, 0x1c'u8, 0xa6'u8, 0xbc'u8, 0xec'u8, 0x73'u8, 0x90'u8, 0x7b'u8, 0xcf'u8, 0x59'u8, 0x8f'u8, 0xa1'u8, 0xf9'u8, 0x2d'u8,
    0xf2'u8, 0xb1'u8, 0x00'u8, 0x94'u8, 0x37'u8, 0x9f'u8, 0xd0'u8, 0x2e'u8, 0x9c'u8, 0x6e'u8, 0x28'u8, 0x3f'u8, 0x80'u8, 0xf0'u8, 0x3d'u8, 0xd3'u8,
    0x25'u8, 0x8a'u8, 0xb5'u8, 0xe7'u8, 0x42'u8, 0xb3'u8, 0xc7'u8, 0xea'u8, 0xf7'u8, 0x4c'u8, 0x11'u8, 0x33'u8, 0x03'u8, 0xa2'u8, 0xac'u8, 0x60'u8
  ]

  S1*: array[256, uint32] = [
    0x00636363'u32, 0x007c7c7c'u32, 0x00777777'u32, 0x007b7b7b'u32, 0x00f2f2f2'u32, 0x006b6b6b'u32, 0x006f6f6f'u32, 0x00c5c5c5'u32,
    0x00303030'u32, 0x00010101'u32, 0x00676767'u32, 0x002b2b2b'u32, 0x00fefefe'u32, 0x00d7d7d7'u32, 0x00ababab'u32, 0x00767676'u32,
    0x00cacaca'u32, 0x00828282'u32, 0x00c9c9c9'u32, 0x007d7d7d'u32, 0x00fafafa'u32, 0x00595959'u32, 0x00474747'u32, 0x00f0f0f0'u32,
    0x00adadad'u32, 0x00d4d4d4'u32, 0x00a2a2a2'u32, 0x00afafaf'u32, 0x009c9c9c'u32, 0x00a4a4a4'u32, 0x00727272'u32, 0x00c0c0c0'u32,
    0x00b7b7b7'u32, 0x00fdfdfd'u32, 0x00939393'u32, 0x00262626'u32, 0x00363636'u32, 0x003f3f3f'u32, 0x00f7f7f7'u32, 0x00cccccc'u32,
    0x00343434'u32, 0x00a5a5a5'u32, 0x00e5e5e5'u32, 0x00f1f1f1'u32, 0x00717171'u32, 0x00d8d8d8'u32, 0x00313131'u32, 0x00151515'u32,
    0x00040404'u32, 0x00c7c7c7'u32, 0x00232323'u32, 0x00c3c3c3'u32, 0x00181818'u32, 0x00969696'u32, 0x00050505'u32, 0x009a9a9a'u32,
    0x00070707'u32, 0x00121212'u32, 0x00808080'u32, 0x00e2e2e2'u32, 0x00ebebeb'u32, 0x00272727'u32, 0x00b2b2b2'u32, 0x00757575'u32,
    0x00090909'u32, 0x00838383'u32, 0x002c2c2c'u32, 0x001a1a1a'u32, 0x001b1b1b'u32, 0x006e6e6e'u32, 0x005a5a5a'u32, 0x00a0a0a0'u32,
    0x00525252'u32, 0x003b3b3b'u32, 0x00d6d6d6'u32, 0x00b3b3b3'u32, 0x00292929'u32, 0x00e3e3e3'u32, 0x002f2f2f'u32, 0x00848484'u32,
    0x00535353'u32, 0x00d1d1d1'u32, 0x00000000'u32, 0x00ededed'u32, 0x00202020'u32, 0x00fcfcfc'u32, 0x00b1b1b1'u32, 0x005b5b5b'u32,
    0x006a6a6a'u32, 0x00cbcbcb'u32, 0x00bebebe'u32, 0x00393939'u32, 0x004a4a4a'u32, 0x004c4c4c'u32, 0x00585858'u32, 0x00cfcfcf'u32,
    0x00d0d0d0'u32, 0x00efefef'u32, 0x00aaaaaa'u32, 0x00fbfbfb'u32, 0x00434343'u32, 0x004d4d4d'u32, 0x00333333'u32, 0x00858585'u32,
    0x00454545'u32, 0x00f9f9f9'u32, 0x00020202'u32, 0x007f7f7f'u32, 0x00505050'u32, 0x003c3c3c'u32, 0x009f9f9f'u32, 0x00a8a8a8'u32,
    0x00515151'u32, 0x00a3a3a3'u32, 0x00404040'u32, 0x008f8f8f'u32, 0x00929292'u32, 0x009d9d9d'u32, 0x00383838'u32, 0x00f5f5f5'u32,
    0x00bcbcbc'u32, 0x00b6b6b6'u32, 0x00dadada'u32, 0x00212121'u32, 0x00101010'u32, 0x00ffffff'u32, 0x00f3f3f3'u32, 0x00d2d2d2'u32,
    0x00cdcdcd'u32, 0x000c0c0c'u32, 0x00131313'u32, 0x00ececec'u32, 0x005f5f5f'u32, 0x00979797'u32, 0x00444444'u32, 0x00171717'u32,
    0x00c4c4c4'u32, 0x00a7a7a7'u32, 0x007e7e7e'u32, 0x003d3d3d'u32, 0x00646464'u32, 0x005d5d5d'u32, 0x00191919'u32, 0x00737373'u32,
    0x00606060'u32, 0x00818181'u32, 0x004f4f4f'u32, 0x00dcdcdc'u32, 0x00222222'u32, 0x002a2a2a'u32, 0x00909090'u32, 0x00888888'u32,
    0x00464646'u32, 0x00eeeeee'u32, 0x00b8b8b8'u32, 0x00141414'u32, 0x00dedede'u32, 0x005e5e5e'u32, 0x000b0b0b'u32, 0x00dbdbdb'u32,
    0x00e0e0e0'u32, 0x00323232'u32, 0x003a3a3a'u32, 0x000a0a0a'u32, 0x00494949'u32, 0x00060606'u32, 0x00242424'u32, 0x005c5c5c'u32,
    0x00c2c2c2'u32, 0x00d3d3d3'u32, 0x00acacac'u32, 0x00626262'u32, 0x00919191'u32, 0x00959595'u32, 0x00e4e4e4'u32, 0x00797979'u32,
    0x00e7e7e7'u32, 0x00c8c8c8'u32, 0x00373737'u32, 0x006d6d6d'u32, 0x008d8d8d'u32, 0x00d5d5d5'u32, 0x004e4e4e'u32, 0x00a9a9a9'u32,
    0x006c6c6c'u32, 0x00565656'u32, 0x00f4f4f4'u32, 0x00eaeaea'u32, 0x00656565'u32, 0x007a7a7a'u32, 0x00aeaeae'u32, 0x00080808'u32,
    0x00bababa'u32, 0x00787878'u32, 0x00252525'u32, 0x002e2e2e'u32, 0x001c1c1c'u32, 0x00a6a6a6'u32, 0x00b4b4b4'u32, 0x00c6c6c6'u32,
    0x00e8e8e8'u32, 0x00dddddd'u32, 0x00747474'u32, 0x001f1f1f'u32, 0x004b4b4b'u32, 0x00bdbdbd'u32, 0x008b8b8b'u32, 0x008a8a8a'u32,
    0x00707070'u32, 0x003e3e3e'u32, 0x00b5b5b5'u32, 0x00666666'u32, 0x00484848'u32, 0x00030303'u32, 0x00f6f6f6'u32, 0x000e0e0e'u32,
    0x00616161'u32, 0x00353535'u32, 0x00575757'u32, 0x00b9b9b9'u32, 0x00868686'u32, 0x00c1c1c1'u32, 0x001d1d1d'u32, 0x009e9e9e'u32,
    0x00e1e1e1'u32, 0x00f8f8f8'u32, 0x00989898'u32, 0x00111111'u32, 0x00696969'u32, 0x00d9d9d9'u32, 0x008e8e8e'u32, 0x00949494'u32,
    0x009b9b9b'u32, 0x001e1e1e'u32, 0x00878787'u32, 0x00e9e9e9'u32, 0x00cecece'u32, 0x00555555'u32, 0x00282828'u32, 0x00dfdfdf'u32,
    0x008c8c8c'u32, 0x00a1a1a1'u32, 0x00898989'u32, 0x000d0d0d'u32, 0x00bfbfbf'u32, 0x00e6e6e6'u32, 0x00424242'u32, 0x00686868'u32,
    0x00414141'u32, 0x00999999'u32, 0x002d2d2d'u32, 0x000f0f0f'u32, 0x00b0b0b0'u32, 0x00545454'u32, 0x00bbbbbb'u32, 0x00161616'u32,
  ]
  S2*: array[256, uint32] = [
    0xe200e2e2'u32, 0x4e004e4e'u32, 0x54005454'u32, 0xfc00fcfc'u32, 0x94009494'u32, 0xc200c2c2'u32, 0x4a004a4a'u32, 0xcc00cccc'u32,
    0x62006262'u32, 0x0d000d0d'u32, 0x6a006a6a'u32, 0x46004646'u32, 0x3c003c3c'u32, 0x4d004d4d'u32, 0x8b008b8b'u32, 0xd100d1d1'u32,
    0x5e005e5e'u32, 0xfa00fafa'u32, 0x64006464'u32, 0xcb00cbcb'u32, 0xb400b4b4'u32, 0x97009797'u32, 0xbe00bebe'u32, 0x2b002b2b'u32,
    0xbc00bcbc'u32, 0x77007777'u32, 0x2e002e2e'u32, 0x03000303'u32, 0xd300d3d3'u32, 0x19001919'u32, 0x59005959'u32, 0xc100c1c1'u32,
    0x1d001d1d'u32, 0x06000606'u32, 0x41004141'u32, 0x6b006b6b'u32, 0x55005555'u32, 0xf000f0f0'u32, 0x99009999'u32, 0x69006969'u32,
    0xea00eaea'u32, 0x9c009c9c'u32, 0x18001818'u32, 0xae00aeae'u32, 0x63006363'u32, 0xdf00dfdf'u32, 0xe700e7e7'u32, 0xbb00bbbb'u32,
    0x00000000'u32, 0x73007373'u32, 0x66006666'u32, 0xfb00fbfb'u32, 0x96009696'u32, 0x4c004c4c'u32, 0x85008585'u32, 0xe400e4e4'u32,
    0x3a003a3a'u32, 0x09000909'u32, 0x45004545'u32, 0xaa00aaaa'u32, 0x0f000f0f'u32, 0xee00eeee'u32, 0x10001010'u32, 0xeb00ebeb'u32,
    0x2d002d2d'u32, 0x7f007f7f'u32, 0xf400f4f4'u32, 0x29002929'u32, 0xac00acac'u32, 0xcf00cfcf'u32, 0xad00adad'u32, 0x91009191'u32,
    0x8d008d8d'u32, 0x78007878'u32, 0xc800c8c8'u32, 0x95009595'u32, 0xf900f9f9'u32, 0x2f002f2f'u32, 0xce00cece'u32, 0xcd00cdcd'u32,
    0x08000808'u32, 0x7a007a7a'u32, 0x88008888'u32, 0x38003838'u32, 0x5c005c5c'u32, 0x83008383'u32, 0x2a002a2a'u32, 0x28002828'u32,
    0x47004747'u32, 0xdb00dbdb'u32, 0xb800b8b8'u32, 0xc700c7c7'u32, 0x93009393'u32, 0xa400a4a4'u32, 0x12001212'u32, 0x53005353'u32,
    0xff00ffff'u32, 0x87008787'u32, 0x0e000e0e'u32, 0x31003131'u32, 0x36003636'u32, 0x21002121'u32, 0x58005858'u32, 0x48004848'u32,
    0x01000101'u32, 0x8e008e8e'u32, 0x37003737'u32, 0x74007474'u32, 0x32003232'u32, 0xca00caca'u32, 0xe900e9e9'u32, 0xb100b1b1'u32,
    0xb700b7b7'u32, 0xab00abab'u32, 0x0c000c0c'u32, 0xd700d7d7'u32, 0xc400c4c4'u32, 0x56005656'u32, 0x42004242'u32, 0x26002626'u32,
    0x07000707'u32, 0x98009898'u32, 0x60006060'u32, 0xd900d9d9'u32, 0xb600b6b6'u32, 0xb900b9b9'u32, 0x11001111'u32, 0x40004040'u32,
    0xec00ecec'u32, 0x20002020'u32, 0x8c008c8c'u32, 0xbd00bdbd'u32, 0xa000a0a0'u32, 0xc900c9c9'u32, 0x84008484'u32, 0x04000404'u32,
    0x49004949'u32, 0x23002323'u32, 0xf100f1f1'u32, 0x4f004f4f'u32, 0x50005050'u32, 0x1f001f1f'u32, 0x13001313'u32, 0xdc00dcdc'u32,
    0xd800d8d8'u32, 0xc000c0c0'u32, 0x9e009e9e'u32, 0x57005757'u32, 0xe300e3e3'u32, 0xc300c3c3'u32, 0x7b007b7b'u32, 0x65006565'u32,
    0x3b003b3b'u32, 0x02000202'u32, 0x8f008f8f'u32, 0x3e003e3e'u32, 0xe800e8e8'u32, 0x25002525'u32, 0x92009292'u32, 0xe500e5e5'u32,
    0x15001515'u32, 0xdd00dddd'u32, 0xfd00fdfd'u32, 0x17001717'u32, 0xa900a9a9'u32, 0xbf00bfbf'u32, 0xd400d4d4'u32, 0x9a009a9a'u32,
    0x7e007e7e'u32, 0xc500c5c5'u32, 0x39003939'u32, 0x67006767'u32, 0xfe00fefe'u32, 0x76007676'u32, 0x9d009d9d'u32, 0x43004343'u32,
    0xa700a7a7'u32, 0xe100e1e1'u32, 0xd000d0d0'u32, 0xf500f5f5'u32, 0x68006868'u32, 0xf200f2f2'u32, 0x1b001b1b'u32, 0x34003434'u32,
    0x70007070'u32, 0x05000505'u32, 0xa300a3a3'u32, 0x8a008a8a'u32, 0xd500d5d5'u32, 0x79007979'u32, 0x86008686'u32, 0xa800a8a8'u32,
    0x30003030'u32, 0xc600c6c6'u32, 0x51005151'u32, 0x4b004b4b'u32, 0x1e001e1e'u32, 0xa600a6a6'u32, 0x27002727'u32, 0xf600f6f6'u32,
    0x35003535'u32, 0xd200d2d2'u32, 0x6e006e6e'u32, 0x24002424'u32, 0x16001616'u32, 0x82008282'u32, 0x5f005f5f'u32, 0xda00dada'u32,
    0xe600e6e6'u32, 0x75007575'u32, 0xa200a2a2'u32, 0xef00efef'u32, 0x2c002c2c'u32, 0xb200b2b2'u32, 0x1c001c1c'u32, 0x9f009f9f'u32,
    0x5d005d5d'u32, 0x6f006f6f'u32, 0x80008080'u32, 0x0a000a0a'u32, 0x72007272'u32, 0x44004444'u32, 0x9b009b9b'u32, 0x6c006c6c'u32,
    0x90009090'u32, 0x0b000b0b'u32, 0x5b005b5b'u32, 0x33003333'u32, 0x7d007d7d'u32, 0x5a005a5a'u32, 0x52005252'u32, 0xf300f3f3'u32,
    0x61006161'u32, 0xa100a1a1'u32, 0xf700f7f7'u32, 0xb000b0b0'u32, 0xd600d6d6'u32, 0x3f003f3f'u32, 0x7c007c7c'u32, 0x6d006d6d'u32,
    0xed00eded'u32, 0x14001414'u32, 0xe000e0e0'u32, 0xa500a5a5'u32, 0x3d003d3d'u32, 0x22002222'u32, 0xb300b3b3'u32, 0xf800f8f8'u32,
    0x89008989'u32, 0xde00dede'u32, 0x71007171'u32, 0x1a001a1a'u32, 0xaf00afaf'u32, 0xba00baba'u32, 0xb500b5b5'u32, 0x81008181'u32,
  ]
  X1*: array[256, uint32] = [
    0x52520052'u32, 0x09090009'u32, 0x6a6a006a'u32, 0xd5d500d5'u32, 0x30300030'u32, 0x36360036'u32, 0xa5a500a5'u32, 0x38380038'u32,
    0xbfbf00bf'u32, 0x40400040'u32, 0xa3a300a3'u32, 0x9e9e009e'u32, 0x81810081'u32, 0xf3f300f3'u32, 0xd7d700d7'u32, 0xfbfb00fb'u32,
    0x7c7c007c'u32, 0xe3e300e3'u32, 0x39390039'u32, 0x82820082'u32, 0x9b9b009b'u32, 0x2f2f002f'u32, 0xffff00ff'u32, 0x87870087'u32,
    0x34340034'u32, 0x8e8e008e'u32, 0x43430043'u32, 0x44440044'u32, 0xc4c400c4'u32, 0xdede00de'u32, 0xe9e900e9'u32, 0xcbcb00cb'u32,
    0x54540054'u32, 0x7b7b007b'u32, 0x94940094'u32, 0x32320032'u32, 0xa6a600a6'u32, 0xc2c200c2'u32, 0x23230023'u32, 0x3d3d003d'u32,
    0xeeee00ee'u32, 0x4c4c004c'u32, 0x95950095'u32, 0x0b0b000b'u32, 0x42420042'u32, 0xfafa00fa'u32, 0xc3c300c3'u32, 0x4e4e004e'u32,
    0x08080008'u32, 0x2e2e002e'u32, 0xa1a100a1'u32, 0x66660066'u32, 0x28280028'u32, 0xd9d900d9'u32, 0x24240024'u32, 0xb2b200b2'u32,
    0x76760076'u32, 0x5b5b005b'u32, 0xa2a200a2'u32, 0x49490049'u32, 0x6d6d006d'u32, 0x8b8b008b'u32, 0xd1d100d1'u32, 0x25250025'u32,
    0x72720072'u32, 0xf8f800f8'u32, 0xf6f600f6'u32, 0x64640064'u32, 0x86860086'u32, 0x68680068'u32, 0x98980098'u32, 0x16160016'u32,
    0xd4d400d4'u32, 0xa4a400a4'u32, 0x5c5c005c'u32, 0xcccc00cc'u32, 0x5d5d005d'u32, 0x65650065'u32, 0xb6b600b6'u32, 0x92920092'u32,
    0x6c6c006c'u32, 0x70700070'u32, 0x48480048'u32, 0x50500050'u32, 0xfdfd00fd'u32, 0xeded00ed'u32, 0xb9b900b9'u32, 0xdada00da'u32,
    0x5e5e005e'u32, 0x15150015'u32, 0x46460046'u32, 0x57570057'u32, 0xa7a700a7'u32, 0x8d8d008d'u32, 0x9d9d009d'u32, 0x84840084'u32,
    0x90900090'u32, 0xd8d800d8'u32, 0xabab00ab'u32, 0x00000000'u32, 0x8c8c008c'u32, 0xbcbc00bc'u32, 0xd3d300d3'u32, 0x0a0a000a'u32,
    0xf7f700f7'u32, 0xe4e400e4'u32, 0x58580058'u32, 0x05050005'u32, 0xb8b800b8'u32, 0xb3b300b3'u32, 0x45450045'u32, 0x06060006'u32,
    0xd0d000d0'u32, 0x2c2c002c'u32, 0x1e1e001e'u32, 0x8f8f008f'u32, 0xcaca00ca'u32, 0x3f3f003f'u32, 0x0f0f000f'u32, 0x02020002'u32,
    0xc1c100c1'u32, 0xafaf00af'u32, 0xbdbd00bd'u32, 0x03030003'u32, 0x01010001'u32, 0x13130013'u32, 0x8a8a008a'u32, 0x6b6b006b'u32,
    0x3a3a003a'u32, 0x91910091'u32, 0x11110011'u32, 0x41410041'u32, 0x4f4f004f'u32, 0x67670067'u32, 0xdcdc00dc'u32, 0xeaea00ea'u32,
    0x97970097'u32, 0xf2f200f2'u32, 0xcfcf00cf'u32, 0xcece00ce'u32, 0xf0f000f0'u32, 0xb4b400b4'u32, 0xe6e600e6'u32, 0x73730073'u32,
    0x96960096'u32, 0xacac00ac'u32, 0x74740074'u32, 0x22220022'u32, 0xe7e700e7'u32, 0xadad00ad'u32, 0x35350035'u32, 0x85850085'u32,
    0xe2e200e2'u32, 0xf9f900f9'u32, 0x37370037'u32, 0xe8e800e8'u32, 0x1c1c001c'u32, 0x75750075'u32, 0xdfdf00df'u32, 0x6e6e006e'u32,
    0x47470047'u32, 0xf1f100f1'u32, 0x1a1a001a'u32, 0x71710071'u32, 0x1d1d001d'u32, 0x29290029'u32, 0xc5c500c5'u32, 0x89890089'u32,
    0x6f6f006f'u32, 0xb7b700b7'u32, 0x62620062'u32, 0x0e0e000e'u32, 0xaaaa00aa'u32, 0x18180018'u32, 0xbebe00be'u32, 0x1b1b001b'u32,
    0xfcfc00fc'u32, 0x56560056'u32, 0x3e3e003e'u32, 0x4b4b004b'u32, 0xc6c600c6'u32, 0xd2d200d2'u32, 0x79790079'u32, 0x20200020'u32,
    0x9a9a009a'u32, 0xdbdb00db'u32, 0xc0c000c0'u32, 0xfefe00fe'u32, 0x78780078'u32, 0xcdcd00cd'u32, 0x5a5a005a'u32, 0xf4f400f4'u32,
    0x1f1f001f'u32, 0xdddd00dd'u32, 0xa8a800a8'u32, 0x33330033'u32, 0x88880088'u32, 0x07070007'u32, 0xc7c700c7'u32, 0x31310031'u32,
    0xb1b100b1'u32, 0x12120012'u32, 0x10100010'u32, 0x59590059'u32, 0x27270027'u32, 0x80800080'u32, 0xecec00ec'u32, 0x5f5f005f'u32,
    0x60600060'u32, 0x51510051'u32, 0x7f7f007f'u32, 0xa9a900a9'u32, 0x19190019'u32, 0xb5b500b5'u32, 0x4a4a004a'u32, 0x0d0d000d'u32,
    0x2d2d002d'u32, 0xe5e500e5'u32, 0x7a7a007a'u32, 0x9f9f009f'u32, 0x93930093'u32, 0xc9c900c9'u32, 0x9c9c009c'u32, 0xefef00ef'u32,
    0xa0a000a0'u32, 0xe0e000e0'u32, 0x3b3b003b'u32, 0x4d4d004d'u32, 0xaeae00ae'u32, 0x2a2a002a'u32, 0xf5f500f5'u32, 0xb0b000b0'u32,
    0xc8c800c8'u32, 0xebeb00eb'u32, 0xbbbb00bb'u32, 0x3c3c003c'u32, 0x83830083'u32, 0x53530053'u32, 0x99990099'u32, 0x61610061'u32,
    0x17170017'u32, 0x2b2b002b'u32, 0x04040004'u32, 0x7e7e007e'u32, 0xbaba00ba'u32, 0x77770077'u32, 0xd6d600d6'u32, 0x26260026'u32,
    0xe1e100e1'u32, 0x69690069'u32, 0x14140014'u32, 0x63630063'u32, 0x55550055'u32, 0x21210021'u32, 0x0c0c000c'u32, 0x7d7d007d'u32,
  ]
  X2*: array[256, uint32] = [
    0x30303000'u32, 0x68686800'u32, 0x99999900'u32, 0x1b1b1b00'u32, 0x87878700'u32, 0xb9b9b900'u32, 0x21212100'u32, 0x78787800'u32,
    0x50505000'u32, 0x39393900'u32, 0xdbdbdb00'u32, 0xe1e1e100'u32, 0x72727200'u32, 0x09090900'u32, 0x62626200'u32, 0x3c3c3c00'u32,
    0x3e3e3e00'u32, 0x7e7e7e00'u32, 0x5e5e5e00'u32, 0x8e8e8e00'u32, 0xf1f1f100'u32, 0xa0a0a000'u32, 0xcccccc00'u32, 0xa3a3a300'u32,
    0x2a2a2a00'u32, 0x1d1d1d00'u32, 0xfbfbfb00'u32, 0xb6b6b600'u32, 0xd6d6d600'u32, 0x20202000'u32, 0xc4c4c400'u32, 0x8d8d8d00'u32,
    0x81818100'u32, 0x65656500'u32, 0xf5f5f500'u32, 0x89898900'u32, 0xcbcbcb00'u32, 0x9d9d9d00'u32, 0x77777700'u32, 0xc6c6c600'u32,
    0x57575700'u32, 0x43434300'u32, 0x56565600'u32, 0x17171700'u32, 0xd4d4d400'u32, 0x40404000'u32, 0x1a1a1a00'u32, 0x4d4d4d00'u32,
    0xc0c0c000'u32, 0x63636300'u32, 0x6c6c6c00'u32, 0xe3e3e300'u32, 0xb7b7b700'u32, 0xc8c8c800'u32, 0x64646400'u32, 0x6a6a6a00'u32,
    0x53535300'u32, 0xaaaaaa00'u32, 0x38383800'u32, 0x98989800'u32, 0x0c0c0c00'u32, 0xf4f4f400'u32, 0x9b9b9b00'u32, 0xededed00'u32,
    0x7f7f7f00'u32, 0x22222200'u32, 0x76767600'u32, 0xafafaf00'u32, 0xdddddd00'u32, 0x3a3a3a00'u32, 0x0b0b0b00'u32, 0x58585800'u32,
    0x67676700'u32, 0x88888800'u32, 0x06060600'u32, 0xc3c3c300'u32, 0x35353500'u32, 0x0d0d0d00'u32, 0x01010100'u32, 0x8b8b8b00'u32,
    0x8c8c8c00'u32, 0xc2c2c200'u32, 0xe6e6e600'u32, 0x5f5f5f00'u32, 0x02020200'u32, 0x24242400'u32, 0x75757500'u32, 0x93939300'u32,
    0x66666600'u32, 0x1e1e1e00'u32, 0xe5e5e500'u32, 0xe2e2e200'u32, 0x54545400'u32, 0xd8d8d800'u32, 0x10101000'u32, 0xcecece00'u32,
    0x7a7a7a00'u32, 0xe8e8e800'u32, 0x08080800'u32, 0x2c2c2c00'u32, 0x12121200'u32, 0x97979700'u32, 0x32323200'u32, 0xababab00'u32,
    0xb4b4b400'u32, 0x27272700'u32, 0x0a0a0a00'u32, 0x23232300'u32, 0xdfdfdf00'u32, 0xefefef00'u32, 0xcacaca00'u32, 0xd9d9d900'u32,
    0xb8b8b800'u32, 0xfafafa00'u32, 0xdcdcdc00'u32, 0x31313100'u32, 0x6b6b6b00'u32, 0xd1d1d100'u32, 0xadadad00'u32, 0x19191900'u32,
    0x49494900'u32, 0xbdbdbd00'u32, 0x51515100'u32, 0x96969600'u32, 0xeeeeee00'u32, 0xe4e4e400'u32, 0xa8a8a800'u32, 0x41414100'u32,
    0xdadada00'u32, 0xffffff00'u32, 0xcdcdcd00'u32, 0x55555500'u32, 0x86868600'u32, 0x36363600'u32, 0xbebebe00'u32, 0x61616100'u32,
    0x52525200'u32, 0xf8f8f800'u32, 0xbbbbbb00'u32, 0x0e0e0e00'u32, 0x82828200'u32, 0x48484800'u32, 0x69696900'u32, 0x9a9a9a00'u32,
    0xe0e0e000'u32, 0x47474700'u32, 0x9e9e9e00'u32, 0x5c5c5c00'u32, 0x04040400'u32, 0x4b4b4b00'u32, 0x34343400'u32, 0x15151500'u32,
    0x79797900'u32, 0x26262600'u32, 0xa7a7a700'u32, 0xdedede00'u32, 0x29292900'u32, 0xaeaeae00'u32, 0x92929200'u32, 0xd7d7d700'u32,
    0x84848400'u32, 0xe9e9e900'u32, 0xd2d2d200'u32, 0xbababa00'u32, 0x5d5d5d00'u32, 0xf3f3f300'u32, 0xc5c5c500'u32, 0xb0b0b000'u32,
    0xbfbfbf00'u32, 0xa4a4a400'u32, 0x3b3b3b00'u32, 0x71717100'u32, 0x44444400'u32, 0x46464600'u32, 0x2b2b2b00'u32, 0xfcfcfc00'u32,
    0xebebeb00'u32, 0x6f6f6f00'u32, 0xd5d5d500'u32, 0xf6f6f600'u32, 0x14141400'u32, 0xfefefe00'u32, 0x7c7c7c00'u32, 0x70707000'u32,
    0x5a5a5a00'u32, 0x7d7d7d00'u32, 0xfdfdfd00'u32, 0x2f2f2f00'u32, 0x18181800'u32, 0x83838300'u32, 0x16161600'u32, 0xa5a5a500'u32,
    0x91919100'u32, 0x1f1f1f00'u32, 0x05050500'u32, 0x95959500'u32, 0x74747400'u32, 0xa9a9a900'u32, 0xc1c1c100'u32, 0x5b5b5b00'u32,
    0x4a4a4a00'u32, 0x85858500'u32, 0x6d6d6d00'u32, 0x13131300'u32, 0x07070700'u32, 0x4f4f4f00'u32, 0x4e4e4e00'u32, 0x45454500'u32,
    0xb2b2b200'u32, 0x0f0f0f00'u32, 0xc9c9c900'u32, 0x1c1c1c00'u32, 0xa6a6a600'u32, 0xbcbcbc00'u32, 0xececec00'u32, 0x73737300'u32,
    0x90909000'u32, 0x7b7b7b00'u32, 0xcfcfcf00'u32, 0x59595900'u32, 0x8f8f8f00'u32, 0xa1a1a100'u32, 0xf9f9f900'u32, 0x2d2d2d00'u32,
    0xf2f2f200'u32, 0xb1b1b100'u32, 0x00000000'u32, 0x94949400'u32, 0x37373700'u32, 0x9f9f9f00'u32, 0xd0d0d000'u32, 0x2e2e2e00'u32,
    0x9c9c9c00'u32, 0x6e6e6e00'u32, 0x28282800'u32, 0x3f3f3f00'u32, 0x80808000'u32, 0xf0f0f000'u32, 0x3d3d3d00'u32, 0xd3d3d300'u32,
    0x25252500'u32, 0x8a8a8a00'u32, 0xb5b5b500'u32, 0xe7e7e700'u32, 0x42424200'u32, 0xb3b3b300'u32, 0xc7c7c700'u32, 0xeaeaea00'u32,
    0xf7f7f700'u32, 0x4c4c4c00'u32, 0x11111100'u32, 0x33333300'u32, 0x03030300'u32, 0xa2a2a200'u32, 0xacacac00'u32, 0x60606000'u32,
  ]
  KRK*: array[3, array[4, uint32]] = [
    [0x517cc1b7'u32, 0x27220a94'u32, 0xfe13abe8'u32, 0xfa9a6ee0'u32],
    [0x6db14acc'u32, 0x9e21c820'u32, 0xff28b1d5'u32, 0xef5de2b0'u32],
    [0xdb92371d'u32, 0x2126e970'u32, 0x03249775'u32, 0x04e8c90e'u32],
  ]

template extend[T: SomeUnsignedInt](b: uint8): T =
  var output: T = 0
  for i in static(0 ..< sizeof(T)):
    output = output or (T(b) shl (i * 8))

  output

# Helper for bit-sliced matrix multiplication
template applyMatrixGeneric[T](v: T, m: static array[8, uint8]): T =
  var res: T = 0
  res ^= (T(0) - ((v shr 0) and extend[T](1))) and extend[T](m[0])
  res ^= (T(0) - ((v shr 1) and extend[T](1))) and extend[T](m[1])
  res ^= (T(0) - ((v shr 2) and extend[T](1))) and extend[T](m[2])
  res ^= (T(0) - ((v shr 3) and extend[T](1))) and extend[T](m[3])
  res ^= (T(0) - ((v shr 4) and extend[T](1))) and extend[T](m[4])
  res ^= (T(0) - ((v shr 5) and extend[T](1))) and extend[T](m[5])
  res ^= (T(0) - ((v shr 6) and extend[T](1))) and extend[T](m[6])
  res ^= (T(0) - ((v shr 7) and extend[T](1))) and extend[T](m[7])
  res

# Helper for tower field inversion (from aes.nim)
template towerInvGeneric[T](state: T): T =
  var x = state
  var a1, a2, a3, a4, a5, a6: T

  a1 = x
  a1 ^= (x and extend[T](0xF0'u8)) shr 4
  a2 = ((x and extend[T](0xCC'u8)) shr 2) or ((x and extend[T](0x33'u8)) shl 2)
  a3 = x and a1
  a3 ^= (a3 and extend[T](0xAA'u8)) shr 1
  a3 ^= (((x shl 1) and a1) xor ((a1 shl 1) and x)) and extend[T](0xAA'u8)
  a4 = a2 and a1
  a4 ^= (a4 and extend[T](0xAA'u8)) shr 1
  a4 ^= (((a2 shl 1) and a1) xor ((a1 shl 1) and a2)) and extend[T](0xAA'u8)
  a5 = (a3 and extend[T](0xCC'u8)) shr 2
  a3 ^= ((a4 shl 2) xor a4) and extend[T](0xCC'u8)
  a4 = a5 and extend[T](0x22'u8)
  a4 |= a4 shr 1
  a4 ^= (a5 shl 1) and extend[T](0x22'u8)
  a3 ^= a4
  a5 = a3 and extend[T](0xA0'u8)
  a5 |= a5 shr 1
  a5 ^= (a3 shl 1) and extend[T](0xA0'u8)
  a4 = a5 and extend[T](0xC0'u8)
  a6 = a4 shr 2
  a4 ^= (a5 shl 2) and extend[T](0xC0'u8)
  a5 = a6 and extend[T](0x20'u8)
  a5 |= a5 shr 1
  a5 ^= (a6 shl 1) and extend[T](0x20'u8)
  a4 |= a5
  a3 ^= a4 shr 4
  a3 &= extend[T](0x0F'u8)
  a2 = a3
  a2 ^= (a3 and extend[T](0x0C'u8)) shr 2
  a4 = a3 and a2
  a4 ^= (a4 and extend[T](0x0A'u8)) shr 1
  a4 ^= (((a3 shl 1) and a2) xor ((a2 shl 1) and a3)) and extend[T](0x0A'u8)
  a5 = a4 and extend[T](0x08'u8)
  a5 |= a5 shr 1
  a5 ^= (a4 shl 1) and extend[T](0x08'u8)
  a4 ^= a5 shr 2
  a4 &= extend[T](0x03'u8)
  a4 ^= (a4 and extend[T](0x02'u8)) shr 1
  a4 |= a4 shl 2
  a3 = a2 and a4
  a3 ^= (a3 and extend[T](0x0A'u8)) shr 1
  a3 ^= (((a2 shl 1) and a4) xor ((a4 shl 1) and a2)) and extend[T](0x0A'u8)
  a3 |= a3 shl 4
  a2 = ((a1 and extend[T](0xCC'u8)) shr 2) or ((a1 and extend[T](0x33'u8)) shl 2)
  x = a1 and a3
  x ^= (x and extend[T](0xAA'u8)) shr 1
  x ^= (((a1 shl 1) and a3) xor ((a3 shl 1) and a1)) and extend[T](0xAA'u8)
  a4 = a2 and a3
  a4 ^= (a4 and extend[T](0xAA'u8)) shr 1
  a4 ^= (((a2 shl 1) and a3) xor ((a3 shl 1) and a2)) and extend[T](0xAA'u8)
  a5 = (x and extend[T](0xCC'u8)) shr 2
  x ^= ((a4 shl 2) xor a4) and extend[T](0xCC'u8)
  a4 = a5 and extend[T](0x22'u8)
  a4 |= a4 shr 1
  a4 ^= (a5 shl 1) and extend[T](0x22'u8)
  x ^= a4
  x

# ARIA SBox1 bit-sliced (AES S-Box)
template SBox1Generic[T](state: T): T =
  var x = state
  # 1. Linear part (AES In-Matrix)
  var y = ((x and extend[T](0xFE'u8)) shr 1) or ((x and extend[T](0x01'u8)) shl 7)
  x &= extend[T](0xDD'u8)
  x ^= y and extend[T](0x57'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x1C'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x4A'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x42'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x64'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0xE0'u8)

  # 2. GF(2^8) Inversion
  x = towerInvGeneric(x)

  # 3. Linear part (AES Out-Matrix)
  y = ((x and extend[T](0xFE'u8)) shr 1) or ((x and extend[T](0x01'u8)) shl 7)
  x &= extend[T](0x39'u8)
  x ^= y and extend[T](0x3F'u8)
  y = ((y and extend[T](0xFC'u8)) shr 2) or ((y and extend[T](0x03'u8)) shl 6)
  x ^= y and extend[T](0x97'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x9B'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x3C'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0xDD'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x72'u8)
  x ^= extend[T](0x63'u8)
  x

# ARIA SBox2 bit-sliced
template SBox2Generic[T](state: T): T =
  var x = state
  # 1. Linear part (AES In-Matrix)
  var y = ((x and extend[T](0xFE'u8)) shr 1) or ((x and extend[T](0x01'u8)) shl 7)
  x &= extend[T](0xDD'u8)
  x ^= y and extend[T](0x57'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x1C'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x4A'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x42'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x64'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0xE0'u8)

  # 2. GF(2^8) Inversion
  x = towerInvGeneric(x)

  # 3. Linear part (S2 Out-Matrix)
  x = applyMatrixGeneric(x, [0xAC'u8, 0x9B'u8, 0x98'u8, 0xDE'u8, 0x74'u8, 0x94'u8, 0x51'u8, 0x96'u8])
  x ^= extend[T](0xE2'u8)
  x

# ARIA SBox3 bit-sliced (Inverse S1)
template SBox3Generic[T](state: T): T =
  var x = state
  x ^= extend[T](0x63'u8)
  # 1. Linear part (AES Out-Matrix Inverse)
  var y = ((x and extend[T](0xFE'u8)) shr 1) or ((x and extend[T](0x01'u8)) shl 7)
  x &= extend[T](0xFD'u8)
  x ^= y and extend[T](0x5E'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0xF3'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0xF5'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x78'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x77'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x15'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0xA5'u8)

  # 2. GF(2^8) Inversion
  x = towerInvGeneric(x)

  # 3. Linear part (AES In-Matrix Inverse)
  y = ((x and extend[T](0xFE'u8)) shr 1) or ((x and extend[T](0x01'u8)) shl 7)
  x &= extend[T](0xB5'u8)
  x ^= y and extend[T](0x40'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x80'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x16'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0xEB'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x97'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0xFB'u8)
  y = ((y and extend[T](0xFE'u8)) shr 1) or ((y and extend[T](0x01'u8)) shl 7)
  x ^= y and extend[T](0x7D'u8)
  x

# ARIA SBox4 bit-sliced (Inverse S2)
template SBox4Generic[T](state: T): T =
  var x = state
  x ^= extend[T](0xE2'u8)
  # 1. Linear part (S2 Out-Matrix Inverse)
  x = applyMatrixGeneric(x, [0xA6'u8, 0xA0'u8, 0xB9'u8, 0x9D'u8, 0xF3'u8, 0x4F'u8, 0x15'u8, 0x6A'u8])
  # 2. GF(2^8) Inversion
  x = towerInvGeneric(x)
  # 3. Linear part (AES In-Matrix Inverse)
  x = applyMatrixGeneric(x, [0x01'u8, 0xBC'u8, 0x5C'u8, 0xB0'u8, 0xF3'u8, 0xE7'u8, 0x03'u8, 0xDF'u8])
  x

const
  # declare ARIA rounds constant
  ARIA128Rounds*: int = 12
  ARIA192Rounds*: int = 14
  ARIA256Rounds*: int = 16

  # declare ARIA key size constant
  ARIA128KeySize*: int = 16
  ARIA192KeySize*: int = 24
  ARIA256KeySize*: int = 32

  # declare ARIA block size constant
  ARIABlockSize*: int = 16

template roundNumber*(keySize: static int): static int =
  when keySize == 16:
    ARIA128Rounds
  elif keySize == 24:
    ARIA192Rounds
  else:
    ARIA256Rounds

template roundKeySize*(keySize: static int): static int =
  when keySize == 16:
    (ARIA128Rounds + 1) * 4
  elif keySize == 24:
    (ARIA192Rounds + 1) * 4
  else:
    (ARIA256Rounds + 1) * 4

type
  # declare ARIA generic context
  ARIACtx*[keySize: static int] = object
    encryptKey*: array[roundKeySize(keySize), uint32]
    decryptKey*: array[roundKeySize(keySize), uint32]

  # declare ARIA-128/192/256 context
  ARIA128Ctx* = ARIACtx[16]
  ARIA192Ctx* = ARIACtx[24]
  ARIA256Ctx* = ARIACtx[32]

template roundNumber*[keySize: static int](ctx: ARIACtx[keySize]): static int =
  when keySize == 16:
    ARIA128Rounds
  elif keySize == 24:
    ARIA192Rounds
  else:
    ARIA256Rounds

template roundKeySize*[keySize: static int](ctx: ARIACtx[keySize]): static int =
  when keySize == 16:
    (ARIA128Rounds + 1) * 4
  elif keySize == 24:
    (ARIA192Rounds + 1) * 4
  else:
    (ARIA256Rounds + 1) * 4
#[
# extend key
template extendKey[N: static int](roundKey: var array[N, uint128], w0, w1, w2, w3: uint128): void =
  # when keybits is over 128
  roundKey[0] = w0 xor rotateRightBits(w1, 19)
  roundKey[1] = w1 xor rotateRightBits(w2, 19)
  roundKey[2] = w2 xor rotateRightBits(w3, 19)
  roundKey[3] = rotateRightBits(w0, 19) xor w3
  roundKey[4] = w0 xor rotateRightBits(w1, 31)
  roundKey[5] = w1 xor rotateRightBits(w2, 31)
  roundKey[6] = w2 xor rotateRightBits(w3, 31)
  roundKey[7] = rotateRightBits(w0, 31) xor w3
  roundKey[8] = w0 xor rotateLeftBits(w1, 61)
  roundKey[9] = w1 xor rotateLeftBits(w2, 61)
  roundKey[10] = w2 xor rotateLeftBits(w3, 61)
  roundKey[11] = rotateLeftBits(w0, 61) xor w3
  roundKey[12] = w0 xor rotateLeftBits(w1, 31)

  # when keybits is over 192
  when N > 13:
    roundKey[13] = w1 xor rotateLeftBits(w2, 31)
    roundKey[14] = w2 xor rotateLeftBits(w3, 31)
    # when keybits is over 256
    when N == 17:
      roundKey[15] = rotateLeftBits(w0, 31) xor w3
      roundKey[16] = w0 xor rotateLeftBits(w1, 19)

template sub1*(input: var uint128): void =
  var bytes: array[16, uint8]
  store128(bytes.toSliceArray(0, 15), input)
  unroll(i, 0, 3):
    block:
      bytes[i*4 + 0] = SBox1[bytes[i*4 + 0]]
      bytes[i*4 + 1] = SBox2[bytes[i*4 + 1]]
      bytes[i*4 + 2] = SBox3[bytes[i*4 + 2]]
      bytes[i*4 + 3] = SBox4[bytes[i*4 + 3]]
  input = load128(bytes.toSliceArray(0, 15))

template sub2*(input: var uint128): void =
  var bytes: ptr array[16, uint8] = cast[ptr array[16, uint8]](addr input.value)
  unroll(i, 0, 3):
      

# Optimized ariaA using 32-bit words
template ariaA*(input: var uint128) =
  var x: array[16, uint8] = toBytes(input)

  let t0 = x[0] xor x[7] xor x[10] xor x[13]
  let t1 = x[1] xor x[6] xor x[11] xor x[12]
  let t2 = x[2] xor x[5] xor x[8] xor x[15]
  let t3 = x[3] xor x[4] xor x[9] xor x[14]

  var r: array[16, uint8]
  r[0] = t3 xor x[6] xor x[8] xor x[13]
  r[1] = t2 xor x[7] xor x[9] xor x[12]
  r[2] = t1 xor x[4] xor x[10] xor x[15]
  r[3] = t0 xor x[5] xor x[11] xor x[14]
  r[4] = x[0] xor t2 xor x[11] xor x[14]
  r[5] = x[1] xor t3 xor x[10] xor x[15]
  r[6] = t0 xor x[2] xor x[9] xor x[12]
  r[7] = t1 xor x[3] xor x[8] xor x[13]
  r[8] = t0 xor x[1] xor x[4] xor x[15]
  r[9] = x[0] xor t1 xor x[5] xor x[14]
  r[10] = t2 xor x[3] xor x[6] xor x[13]
  r[11] = x[2] xor t3 xor x[7] xor x[12]
  r[12] = t1 xor x[2] xor x[7] xor x[9]
  r[13] = t0 xor x[3] xor x[6] xor x[8]
  r[14] = x[0] xor t3 xor x[5] xor x[11]
  r[15] = x[1] xor t2 xor x[4] xor x[10]

  input = toBigUint(r)

# aria odd round template for uint128
template oddRoundV(roundKey: uint128, state: var uint128): void =
  state = state xor roundKey
  sub1(state)
  ariaA(state)

# aria even round template for uint128
template evenRoundV(roundKey: uint128, state: var uint128): void =
  state = state xor roundKey
  sub2(state)
  ariaA(state)

# aria odd round template for uint128 returning
template oddRound(roundKey: uint128, state: uint128): uint128 =
  var res = state xor roundKey
  sub1(res)
  ariaA(res)
  res

# aria even round template for uint128 returning
template evenRound(roundKey: uint128, state: uint128): uint128 =
  var res = state xor roundKey
  sub2(res)
  ariaA(res)
  res

# aria encrypt core
template ariaEncryptC(ctx: ARIACtx, input, output: slicearray[16, uint8]): void = 
  var state: uint128 = load128(input)

  oddRoundV(ctx.roundKeyE[0], state)

  unroll(i, 0, roundNumber(ctx) div 2 - 2):
    evenRoundV(ctx.roundKeyE[i * 2 + 1], state)
    oddRoundV(ctx.roundKeyE[i * 2 + 2], state)

  let rounds: int = roundNumber(ctx)
  state = state xor ctx.roundKeyE[rounds - 1]
  sub2(state)
  state = state xor ctx.roundKeyE[rounds]

  store128(output, state)

# aria decrypt core
template ariaDecryptC(ctx: ARIACtx, input, output: slicearray[16, uint8]): void = 
  var state: uint128 = load128(input)

  oddRoundV(ctx.roundKeyD[0], state)

  for i in 0 ..< roundNumber(ctx) div 2 - 1:
    evenRoundV(ctx.roundKeyD[i * 2 + 1], state)
    oddRoundV(ctx.roundKeyD[i * 2 + 2], state)

  let rounds: int = roundNumber(ctx)
  state = state xor ctx.roundKeyD[rounds - 1]
  sub2(state)
  state = state xor ctx.roundKeyD[rounds]

  store128(output, state)

# aria init core
template ariaInitC[keyBits: static int, N: static int](ctx: var ARIACtx[keyBits], input: slicearray[N, uint8]): void = 
  # set constant
  var C1, C2, C3: uint128
  C1 = load128([0x51'u8, 0x7c'u8, 0xc1'u8, 0xb7'u8, 0x27'u8, 0x22'u8, 0x0a'u8, 0x94'u8, 0xfe'u8, 0x13'u8, 0xab'u8, 0xe8'u8, 0xfa'u8, 0x9a'u8, 0x6e'u8, 0xe0'u8])
  C2 = load128([0x6d'u8, 0xb1'u8, 0x4a'u8, 0xcc'u8, 0x9e'u8, 0x21'u8, 0xc8'u8, 0x20'u8, 0xff'u8, 0x28'u8, 0xb1'u8, 0xd5'u8, 0xef'u8, 0x5d'u8, 0xe2'u8, 0xb0'u8])
  C3 = load128([0xdb'u8, 0x92'u8, 0x37'u8, 0x1d'u8, 0x21'u8, 0x26'u8, 0xe9'u8, 0x70'u8, 0x03'u8, 0x24'u8, 0x97'u8, 0x75'u8, 0x04'u8, 0xe8'u8, 0xc9'u8, 0x0e'u8])

  var ck1, ck2, ck3: uint128
  var keyLeft, keyRight: uint128
  keyLeft = load128(input.toSliceArray(0, 15))
  
  when N == 16:
    ck1 = C1; ck2 = C2; ck3 = C3
  elif N == 24:
    ck1 = C2; ck2 = C3; ck3 = C1
    var kr: array[16, uint8] = [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    unroll(i, 0, 7): kr[i] = input[16 + i]
    keyRight = load128(kr)
  elif N == 32:
    ck1 = C3; ck2 = C1; ck3 = C2
    keyRight = load128(input.toSliceArray(16, 31))

  # set round key
  let w0: uint128 = keyLeft
  let w1: uint128 = oddRound(ck1, w0) xor keyRight
  let w2: uint128 = evenRound(ck2, w1) xor w0
  let w3: uint128 = oddRound(ck3, w2) xor w1

  # extend key
  extendKey(ctx.roundKeyE, w0, w1, w2, w3)

  # set decrypt round key
  ctx.roundKeyD[0] = ctx.roundKeyE[roundKeySize(ctx) - 1]
  unroll(i, 1, roundKeySize(ctx) - 2):
    block:
      ctx.roundKeyD[i] = ctx.roundKeyE[roundKeySize(ctx) - 1 - i]
      ariaA(ctx.roundKeyD[i])
  ctx.roundKeyD[roundKeySize(ctx) - 1] = ctx.roundKeyE[0]
]#


template byteReverse32(x: uint32): uint32 =
  (x shr 24) or ((x shr 8) and 0xff00'u32) or
    ((x shl 8) and 0xff0000'u32) or (x shl 24)

template ariaBrf(x: uint32, y: int): uint8 =
  uint8((x shr (8 * y)) and 0xff'u32)

template loadBE32(src: openArray[uint8]; off: int): uint32 =
  (uint32(src[off]) shl 24) or (uint32(src[off + 1]) shl 16) or
    (uint32(src[off + 2]) shl 8) or uint32(src[off + 3])

template sbl1M(t0, t1, t2, t3: var uint32): void =
  t0 = S1[ariaBrf(t0, 3)] xor S2[ariaBrf(t0, 2)] xor X1[ariaBrf(t0, 1)] xor X2[ariaBrf(t0, 0)]
  t1 = S1[ariaBrf(t1, 3)] xor S2[ariaBrf(t1, 2)] xor X1[ariaBrf(t1, 1)] xor X2[ariaBrf(t1, 0)]
  t2 = S1[ariaBrf(t2, 3)] xor S2[ariaBrf(t2, 2)] xor X1[ariaBrf(t2, 1)] xor X2[ariaBrf(t2, 0)]
  t3 = S1[ariaBrf(t3, 3)] xor S2[ariaBrf(t3, 2)] xor X1[ariaBrf(t3, 1)] xor X2[ariaBrf(t3, 0)]

template sbl2M(t0, t1, t2, t3: var uint32): void =
  t0 = X1[ariaBrf(t0, 3)] xor X2[ariaBrf(t0, 2)] xor S1[ariaBrf(t0, 1)] xor S2[ariaBrf(t0, 0)]
  t1 = X1[ariaBrf(t1, 3)] xor X2[ariaBrf(t1, 2)] xor S1[ariaBrf(t1, 1)] xor S2[ariaBrf(t1, 0)]
  t2 = X1[ariaBrf(t2, 3)] xor X2[ariaBrf(t2, 2)] xor S1[ariaBrf(t2, 1)] xor S2[ariaBrf(t2, 0)]
  t3 = X1[ariaBrf(t3, 3)] xor X2[ariaBrf(t3, 2)] xor S1[ariaBrf(t3, 1)] xor S2[ariaBrf(t3, 0)]

template ariaP(t0, t1, t2, t3: var uint32): void =
  t1 = ((t1 shl 8) and 0xff00ff00'u32) xor ((t1 shr 8) and 0x00ff00ff'u32)
  t2 = rotateRightBits(t2, 16)
  t3 = byteReverse32(t3)

template ariaM(x: uint32; y: var uint32): void =
  y = (x shl 8) xor (x shr 8) xor (x shl 16) xor (x shr 16) xor (x shl 24) xor (x shr 24)

template ariaMM(t0, t1, t2, t3: var uint32): void =
  t1 = t1 xor t2
  t2 = t2 xor t3
  t0 = t0 xor t1
  t3 = t3 xor t1
  t2 = t2 xor t0
  t1 = t1 xor t2

template ariaFO(t0, t1, t2, t3: var uint32): void =
  sbl1M(t0, t1, t2, t3)
  ariaMM(t0, t1, t2, t3)
  ariaP(t0, t1, t2, t3)
  ariaMM(t0, t1, t2, t3)

template ariaFE(t0, t1, t2, t3: var uint32): void =
  sbl2M(t0, t1, t2, t3)
  ariaMM(t0, t1, t2, t3)
  ariaP(t2, t3, t0, t1)
  ariaMM(t0, t1, t2, t3)

template ariaKxl(rk: openArray[uint32]; rkOff: int; t0, t1, t2, t3: var uint32): void =
  t0 = t0 xor rk[rkOff + 0]
  t1 = t1 xor rk[rkOff + 1]
  t2 = t2 xor rk[rkOff + 2]
  t3 = t3 xor rk[rkOff + 3]

template ariaGsrk(N: static int; x, y: array[4, uint32]; roundKey: var openArray[uint32]; rkOff: int): void =
  const Q: int = 4 - (N div 32)
  const R: int = N mod 32
  roundKey[rkOff + 0] = x[0] xor (y[(Q) mod 4] shr R) xor (y[(Q + 3) mod 4] shl (32 - R))
  roundKey[rkOff + 1] = x[1] xor (y[(Q + 1) mod 4] shr R) xor (y[(Q) mod 4] shl (32 - R))
  roundKey[rkOff + 2] = x[2] xor (y[(Q + 2) mod 4] shr R) xor (y[(Q + 1) mod 4] shl (32 - R))
  roundKey[rkOff + 3] = x[3] xor (y[(Q + 3) mod 4] shr R) xor (y[(Q + 2) mod 4] shl (32 - R))

template ariaMakeDecKeys(rk: var openArray[uint32], rounds: static int): void =
  var t0: uint32 = rk[0]
  var t1: uint32 = rk[1]
  var t2: uint32 = rk[2]
  var t3: uint32 = rk[3]

  rk[0] = rk[rounds * 4 + 0]
  rk[1] = rk[rounds * 4 + 1]
  rk[2] = rk[rounds * 4 + 2]
  rk[3] = rk[rounds * 4 + 3]

  rk[rounds * 4 + 0] = t0
  rk[rounds * 4 + 1] = t1
  rk[rounds * 4 + 2] = t2
  rk[rounds * 4 + 3] = t3

  const r = rounds div 2
  for i in static(0 ..< r):
    let a = 4 + (i * 4)
    let z = (rounds * 4 - 4) - (i * 4)

    var st0, st1, st2, st3: uint32
    var mt0, mt1, mt2, mt3: uint32

    ariaM(rk[a + 0], st0); ariaM(rk[a + 1], st1); ariaM(rk[a + 2], st2); ariaM(rk[a + 3], st3)
    ariaMM(st0, st1, st2, st3)
    ariaP(st0, st1, st2, st3)
    ariaMM(st0, st1, st2, st3)

    ariaM(rk[z + 0], mt0); ariaM(rk[z + 1], mt1); ariaM(rk[z + 2], mt2); ariaM(rk[z + 3], mt3)
    ariaMM(mt0, mt1, mt2, mt3)
    ariaP(mt0, mt1, mt2, mt3)
    ariaMM(mt0, mt1, mt2, mt3)

    rk[a + 0] = mt0
    rk[a + 1] = mt1
    rk[a + 2] = mt2
    rk[a + 3] = mt3

    rk[z + 0] = st0
    rk[z + 1] = st1
    rk[z + 2] = st2
    rk[z + 3] = st3

template ariaInitC*[N: static int](ctx: var ARIACtx[N], key: slicearray[N, uint8]): void =
  when N != 16 and N != 24 and N != 32:
    {.error: "ARIA key length must be 16, 24, or 32 bytes".}

  const rounds: int = roundNumber(N)

  var
    w0, w1, w2, w3: array[4, uint32]
    t0, t1, t2, t3: uint32

  when N == 16:
    const q0 = 0
    decodeBE(key.toSliceArray(0, 15), w0.toSliceArray(0, 3))
    zeroMem(addr w1, 16)
  elif N == 24:
    const q0 = 1
    decodeBE(key.toSliceArray(0, 15), w0.toSliceArray(0, 3))
    decodeBE(key.toSliceArray(16, 23), w1.toSliceArray(0, 1))
    zeroMem(addr w1[2], 8)
  else:
    const q0 = 2
    decodeBE(key.toSliceArray(0, 15), w0.toSliceArray(0, 3))
    decodeBE(key.toSliceArray(16, 31), w1.toSliceArray(0, 3))

  t0 = w0[0] xor KRK[q0][0]
  t1 = w0[1] xor KRK[q0][1]
  t2 = w0[2] xor KRK[q0][2]
  t3 = w0[3] xor KRK[q0][3]
  ariaFO(t0, t1, t2, t3)

  w1[0] = w1[0] xor t0
  w1[1] = w1[1] xor t1
  w1[2] = w1[2] xor t2
  w1[3] = w1[3] xor t3
  t0 = w1[0]; t1 = w1[1]; t2 = w1[2]; t3 = w1[3]

  const q1: int = when q0 == 2: 0 else: q0 + 1
  t0 = t0 xor KRK[q1][0]
  t1 = t1 xor KRK[q1][1]
  t2 = t2 xor KRK[q1][2]
  t3 = t3 xor KRK[q1][3]
  ariaFE(t0, t1, t2, t3)

  t0 = t0 xor w0[0]
  t1 = t1 xor w0[1]
  t2 = t2 xor w0[2]
  t3 = t3 xor w0[3]
  w2[0] = t0; w2[1] = t1; w2[2] = t2; w2[3] = t3

  const q2: int = when q1 == 2: 0 else: q1 + 1
  t0 = t0 xor KRK[q2][0]
  t1 = t1 xor KRK[q2][1]
  t2 = t2 xor KRK[q2][2]
  t3 = t3 xor KRK[q2][3]
  ariaFO(t0, t1, t2, t3)

  w3[0] = t0 xor w1[0]
  w3[1] = t1 xor w1[1]
  w3[2] = t2 xor w1[2]
  w3[3] = t3 xor w1[3]

  ariaGsrk(19, w0, w1, ctx.encryptKey, 0)
  ariaGsrk(19, w1, w2, ctx.encryptKey, 4)
  ariaGsrk(19, w2, w3, ctx.encryptKey, 8)
  ariaGsrk(19, w3, w0, ctx.encryptKey, 12)
  ariaGsrk(31, w0, w1, ctx.encryptKey, 16)
  ariaGsrk(31, w1, w2, ctx.encryptKey, 20)
  ariaGsrk(31, w2, w3, ctx.encryptKey, 24)
  ariaGsrk(31, w3, w0, ctx.encryptKey, 28)
  ariaGsrk(67, w0, w1, ctx.encryptKey, 32)
  ariaGsrk(67, w1, w2, ctx.encryptKey, 36)
  ariaGsrk(67, w2, w3, ctx.encryptKey, 40)
  ariaGsrk(67, w3, w0, ctx.encryptKey, 44)
  ariaGsrk(97, w0, w1, ctx.encryptKey, 48)

  when N > 16:
    ariaGsrk(97, w1, w2, ctx.encryptKey, 52)
    ariaGsrk(97, w2, w3, ctx.encryptKey, 56)
    when N > 24:
      ariaGsrk(97, w3, w0, ctx.encryptKey, 60)
      ariaGsrk(109, w0, w1, ctx.encryptKey, 64)

  copyMem(addr ctx.decryptKey[0], addr ctx.encryptKey[0], sizeof(ctx.encryptKey))

  ariaMakeDecKeys(ctx.decryptKey, roundNumber(ctx))

template ariaProcessBlock(roundKey: openArray[uint32]; rounds: static int, input, output: slicearray[16, uint8]): void =
  var
    t0, t1, t2, t3: uint32
    rkOff = 0

  fromBytesBE(input.toSliceArray(0, 3), t0)
  fromBytesBE(input.toSliceArray(4, 7), t1)
  fromBytesBE(input.toSliceArray(8, 11), t2)
  fromBytesBE(input.toSliceArray(12, 15), t3)

  when rounds > 12:
    ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFO(t0, t1, t2, t3)
    ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFE(t0, t1, t2, t3)

  when rounds > 14:
    ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFO(t0, t1, t2, t3)
    ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFE(t0, t1, t2, t3)

  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFO(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFE(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFO(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFE(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFO(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFE(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFO(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFE(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFO(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFE(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4; ariaFO(t0, t1, t2, t3)
  ariaKxl(roundKey, rkOff, t0, t1, t2, t3); rkOff += 4

  let r0 = roundKey[rkOff + 0]
  let r1 = roundKey[rkOff + 1]
  let r2 = roundKey[rkOff + 2]
  let r3 = roundKey[rkOff + 3]

  output[0] = uint8(X1[ariaBrf(t0, 3)]) xor uint8(roundKey[rkOff + 0] shr 24)
  output[1] = uint8(X2[ariaBrf(t0, 2)] shr 8) xor uint8(roundKey[rkOff + 0] shr 16)
  output[2] = uint8(S1[ariaBrf(t0, 1)]) xor uint8(roundKey[rkOff + 0] shr 8)
  output[3] = uint8(S2[ariaBrf(t0, 0)]) xor uint8(roundKey[rkOff + 0])
  output[4] = uint8(X1[ariaBrf(t1, 3)]) xor uint8(roundKey[rkOff + 1] shr 24)
  output[5] = uint8(X2[ariaBrf(t1, 2)] shr 8) xor uint8(roundKey[rkOff + 1] shr 16)
  output[6] = uint8(S1[ariaBrf(t1, 1)]) xor uint8(roundKey[rkOff + 1] shr 8)
  output[7] = uint8(S2[ariaBrf(t1, 0)]) xor uint8(roundKey[rkOff + 1])
  output[8] = uint8(X1[ariaBrf(t2, 3)]) xor uint8(roundKey[rkOff + 2] shr 24)
  output[9] = uint8(X2[ariaBrf(t2, 2)] shr 8) xor uint8(roundKey[rkOff + 2] shr 16)
  output[10] = uint8(S1[ariaBrf(t2, 1)]) xor uint8(roundKey[rkOff + 2] shr 8)
  output[11] = uint8(S2[ariaBrf(t2, 0)]) xor uint8(roundKey[rkOff + 2])
  output[12] = uint8(X1[ariaBrf(t3, 3)]) xor uint8(roundKey[rkOff + 3] shr 24)
  output[13] = uint8(X2[ariaBrf(t3, 2)] shr 8) xor uint8(roundKey[rkOff + 3] shr 16)
  output[14] = uint8(S1[ariaBrf(t3, 1)]) xor uint8(roundKey[rkOff + 3] shr 8)
  output[15] = uint8(S2[ariaBrf(t3, 0)]) xor uint8(roundKey[rkOff + 3])

template ariaEncryptC*[N: static int](ctx: ARIACtx[N], input, output: slicearray[16, uint8]): void =
  ariaProcessBlock(ctx.encryptKey, roundNumber(N), input, output)

template ariaDecryptC*[N: static int](ctx: ARIACtx[N], input, output: slicearray[16, uint8]): void =
  ariaProcessBlock(ctx.decryptKey, roundNumber(N), input, output)

when defined(templateOpt):
  template aria128Init*(ctx: var ARIA128Ctx, key: array[16, uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 15))
  template aria128Init*(ctx: var ARIA128Ctx, key: openArray[uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 15, 16))
  template aria128Init*(ctx: var ARIA128Ctx, key: slicearray[16, uint8]): void =
    ariaInitC(ctx, key)
  template aria128Init*(ctx: ptr ARIA128Ctx, key: ptr array[16, uint8]): void {.importc: "aria128Init", cdecl.} =
    ariaInitC(ctx[], key.toSliceArray(0, 15))

  template aria128Encrypt*(ctx: ARIA128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template aria128Encrypt*(ctx: ARIA128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  template aria128Encrypt*(ctx: ARIA128Ctx, input, output: slicearray[16, uint8]): void =
    ariaEncryptC(ctx, input, output)
  template aria128Encrypt*(ctx: ARIA128Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria128Encrypt", cdecl.} =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template aria128Decrypt*(ctx: ARIA128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template aria128Decrypt*(ctx: ARIA128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  template aria128Decrypt*(ctx: ARIA128Ctx, input, output: slicearray[16, uint8]): void =
    ariaDecryptC(ctx, input, output)
  template aria128Decrypt*(ctx: ARIA128Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria128Decrypt", cdecl.} =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template aria192Init*(ctx: var ARIA192Ctx, key: array[24, uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 23))
  template aria192Init*(ctx: var ARIA192Ctx, key: openArray[uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 23, 24))
  template aria192Init*(ctx: var ARIA192Ctx, key: slicearray[24, uint8]): void =
    ariaInitC(ctx, key)
  template aria192Init*(ctx: ptr ARIA192Ctx, key: ptr array[24, uint8]): void {.importc: "aria192Init", cdecl.} =
    ariaInitC(ctx[], key.toSliceArray(0, 23))

  template aria192Encrypt*(ctx: ARIA192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template aria192Encrypt*(ctx: ARIA192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  template aria192Encrypt*(ctx: ARIA192Ctx, input, output: slicearray[16, uint8]): void =
    ariaEncryptC(ctx, input, output)
  template aria192Encrypt*(ctx: ARIA192Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria192Encrypt", cdecl.} =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template aria192Decrypt*(ctx: ARIA192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template aria192Decrypt*(ctx: ARIA192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  template aria192Decrypt*(ctx: ARIA192Ctx, input, output: slicearray[16, uint8]): void =
    ariaDecryptC(ctx, input, output)
  template aria192Decrypt*(ctx: ARIA192Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria192Decrypt", cdecl.} =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template aria256Init*(ctx: var ARIA256Ctx, key: array[32, uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 31))
  template aria256Init*(ctx: var ARIA256Ctx, key: openArray[uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 31, 32))
  template aria256Init*(ctx: var ARIA256Ctx, key: slicearray[32, uint8]): void =
    ariaInitC(ctx, key)
  template aria256Init*(ctx: ptr ARIA256Ctx, key: ptr array[32, uint8]): void {.importc: "aria256Init", cdecl.} =
    ariaInitC(ctx[], key.toSliceArray(0, 31))

  template aria256Encrypt*(ctx: ARIA256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template aria256Encrypt*(ctx: ARIA256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  template aria256Encrypt*(ctx: ARIA256Ctx, input, output: slicearray[16, uint8]): void =
    ariaEncryptC(ctx, input, output)
  template aria256Encrypt*(ctx: ARIA256Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria256Encrypt", cdecl.} =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template aria256Decrypt*(ctx: ARIA256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template aria256Decrypt*(ctx: ARIA256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  template aria256Decrypt*(ctx: ARIA256Ctx, input, output: slicearray[16, uint8]): void =
    ariaDecryptC(ctx, input, output)
  template aria256Decrypt*(ctx: ARIA256Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria256Decrypt", cdecl.} =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
else:
  proc aria128Init*(ctx: var ARIA128Ctx, key: array[16, uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 15))
  proc aria128Init*(ctx: var ARIA128Ctx, key: openArray[uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 15, 16))
  proc aria128Init*(ctx: var ARIA128Ctx, key: slicearray[16, uint8]): void =
    ariaInitC(ctx, key)
  proc aria128Init*(ctx: ptr ARIA128Ctx, key: ptr array[16, uint8]): void {.importc: "aria128Init", cdecl.} =
    ariaInitC(ctx[], key.toSliceArray(0, 15))

  proc aria128Encrypt*(ctx: ARIA128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc aria128Encrypt*(ctx: ARIA128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  proc aria128Encrypt*(ctx: ARIA128Ctx, input, output: slicearray[16, uint8]): void =
    ariaEncryptC(ctx, input, output)
  proc aria128Encrypt*(ctx: ARIA128Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria128Encrypt", cdecl.} =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc aria128Decrypt*(ctx: ARIA128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc aria128Decrypt*(ctx: ARIA128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  proc aria128Decrypt*(ctx: ARIA128Ctx, input, output: slicearray[16, uint8]): void =
    ariaDecryptC(ctx, input, output)
  proc aria128Decrypt*(ctx: ARIA128Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria128Decrypt", cdecl.} =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc aria192Init*(ctx: var ARIA192Ctx, key: array[24, uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 23))
  proc aria192Init*(ctx: var ARIA192Ctx, key: openArray[uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 23, 24))
  proc aria192Init*(ctx: var ARIA192Ctx, key: slicearray[24, uint8]): void =
    ariaInitC(ctx, key)
  proc aria192Init*(ctx: ptr ARIA192Ctx, key: ptr array[24, uint8]): void {.importc: "aria192Init", cdecl.} =
    ariaInitC(ctx[], key.toSliceArray(0, 23))

  proc aria192Encrypt*(ctx: ARIA192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc aria192Encrypt*(ctx: ARIA192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  proc aria192Encrypt*(ctx: ARIA192Ctx, input, output: slicearray[16, uint8]): void =
    ariaEncryptC(ctx, input, output)
  proc aria192Encrypt*(ctx: ARIA192Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria192Encrypt", cdecl.} =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc aria192Decrypt*(ctx: ARIA192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc aria192Decrypt*(ctx: ARIA192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  proc aria192Decrypt*(ctx: ARIA192Ctx, input, output: slicearray[16, uint8]): void =
    ariaDecryptC(ctx, input, output)
  proc aria192Decrypt*(ctx: ARIA192Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria192Decrypt", cdecl.} =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc aria256Init*(ctx: var ARIA256Ctx, key: array[32, uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 31))
  proc aria256Init*(ctx: var ARIA256Ctx, key: openArray[uint8]): void =
    ariaInitC(ctx, key.toSliceArray(0, 31, 32))
  proc aria256Init*(ctx: var ARIA256Ctx, key: slicearray[32, uint8]): void =
    ariaInitC(ctx, key)
  proc aria256Init*(ctx: ptr ARIA256Ctx, key: ptr array[32, uint8]): void {.importc: "aria256Init", cdecl.} =
    ariaInitC(ctx[], key.toSliceArray(0, 31))

  proc aria256Encrypt*(ctx: ARIA256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc aria256Encrypt*(ctx: ARIA256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaEncryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  proc aria256Encrypt*(ctx: ARIA256Ctx, input, output: slicearray[16, uint8]): void =
    ariaEncryptC(ctx, input, output)
  proc aria256Encrypt*(ctx: ARIA256Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria256Encrypt", cdecl.} =
    ariaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc aria256Decrypt*(ctx: ARIA256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc aria256Decrypt*(ctx: ARIA256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    ariaDecryptC(ctx, input.toSliceArray(0, 15, 16), output.toSliceArray(0, 15, 16))
  proc aria256Decrypt*(ctx: ARIA256Ctx, input, output: slicearray[16, uint8]): void =
    ariaDecryptC(ctx, input, output)
  proc aria256Decrypt*(ctx: ARIA256Ctx, input, output: ptr array[16, uint8]): void {.importc: "aria256Decrypt", cdecl.} =
    ariaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))



