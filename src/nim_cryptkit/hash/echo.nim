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
  Table: array[4, array[256, uint32]] = [
    [
      0xa56363c6'u32, 0x847c7cf8'u32, 0x997777ee'u32, 0x8d7b7bf6'u32, 0x0df2f2ff'u32, 0xbd6b6bd6'u32, 0xb16f6fde'u32, 0x54c5c591'u32,
      0x50303060'u32, 0x03010102'u32, 0xa96767ce'u32, 0x7d2b2b56'u32, 0x19fefee7'u32, 0x62d7d7b5'u32, 0xe6abab4d'u32, 0x9a7676ec'u32,
      0x45caca8f'u32, 0x9d82821f'u32, 0x40c9c989'u32, 0x877d7dfa'u32, 0x15fafaef'u32, 0xeb5959b2'u32, 0xc947478e'u32, 0x0bf0f0fb'u32,
      0xecadad41'u32, 0x67d4d4b3'u32, 0xfda2a25f'u32, 0xeaafaf45'u32, 0xbf9c9c23'u32, 0xf7a4a453'u32, 0x967272e4'u32, 0x5bc0c09b'u32,
      0xc2b7b775'u32, 0x1cfdfde1'u32, 0xae93933d'u32, 0x6a26264c'u32, 0x5a36366c'u32, 0x413f3f7e'u32, 0x02f7f7f5'u32, 0x4fcccc83'u32,
      0x5c343468'u32, 0xf4a5a551'u32, 0x34e5e5d1'u32, 0x08f1f1f9'u32, 0x937171e2'u32, 0x73d8d8ab'u32, 0x53313162'u32, 0x3f15152a'u32,
      0x0c040408'u32, 0x52c7c795'u32, 0x65232346'u32, 0x5ec3c39d'u32, 0x28181830'u32, 0xa1969637'u32, 0x0f05050a'u32, 0xb59a9a2f'u32,
      0x0907070e'u32, 0x36121224'u32, 0x9b80801b'u32, 0x3de2e2df'u32, 0x26ebebcd'u32, 0x6927274e'u32, 0xcdb2b27f'u32, 0x9f7575ea'u32,
      0x1b090912'u32, 0x9e83831d'u32, 0x742c2c58'u32, 0x2e1a1a34'u32, 0x2d1b1b36'u32, 0xb26e6edc'u32, 0xee5a5ab4'u32, 0xfba0a05b'u32,
      0xf65252a4'u32, 0x4d3b3b76'u32, 0x61d6d6b7'u32, 0xceb3b37d'u32, 0x7b292952'u32, 0x3ee3e3dd'u32, 0x712f2f5e'u32, 0x97848413'u32,
      0xf55353a6'u32, 0x68d1d1b9'u32, 0x00000000'u32, 0x2cededc1'u32, 0x60202040'u32, 0x1ffcfce3'u32, 0xc8b1b179'u32, 0xed5b5bb6'u32,
      0xbe6a6ad4'u32, 0x46cbcb8d'u32, 0xd9bebe67'u32, 0x4b393972'u32, 0xde4a4a94'u32, 0xd44c4c98'u32, 0xe85858b0'u32, 0x4acfcf85'u32,
      0x6bd0d0bb'u32, 0x2aefefc5'u32, 0xe5aaaa4f'u32, 0x16fbfbed'u32, 0xc5434386'u32, 0xd74d4d9a'u32, 0x55333366'u32, 0x94858511'u32,
      0xcf45458a'u32, 0x10f9f9e9'u32, 0x06020204'u32, 0x817f7ffe'u32, 0xf05050a0'u32, 0x443c3c78'u32, 0xba9f9f25'u32, 0xe3a8a84b'u32,
      0xf35151a2'u32, 0xfea3a35d'u32, 0xc0404080'u32, 0x8a8f8f05'u32, 0xad92923f'u32, 0xbc9d9d21'u32, 0x48383870'u32, 0x04f5f5f1'u32,
      0xdfbcbc63'u32, 0xc1b6b677'u32, 0x75dadaaf'u32, 0x63212142'u32, 0x30101020'u32, 0x1affffe5'u32, 0x0ef3f3fd'u32, 0x6dd2d2bf'u32,
      0x4ccdcd81'u32, 0x140c0c18'u32, 0x35131326'u32, 0x2fececc3'u32, 0xe15f5fbe'u32, 0xa2979735'u32, 0xcc444488'u32, 0x3917172e'u32,
      0x57c4c493'u32, 0xf2a7a755'u32, 0x827e7efc'u32, 0x473d3d7a'u32, 0xac6464c8'u32, 0xe75d5dba'u32, 0x2b191932'u32, 0x957373e6'u32,
      0xa06060c0'u32, 0x98818119'u32, 0xd14f4f9e'u32, 0x7fdcdca3'u32, 0x66222244'u32, 0x7e2a2a54'u32, 0xab90903b'u32, 0x8388880b'u32,
      0xca46468c'u32, 0x29eeeec7'u32, 0xd3b8b86b'u32, 0x3c141428'u32, 0x79dedea7'u32, 0xe25e5ebc'u32, 0x1d0b0b16'u32, 0x76dbdbad'u32,
      0x3be0e0db'u32, 0x56323264'u32, 0x4e3a3a74'u32, 0x1e0a0a14'u32, 0xdb494992'u32, 0x0a06060c'u32, 0x6c242448'u32, 0xe45c5cb8'u32,
      0x5dc2c29f'u32, 0x6ed3d3bd'u32, 0xefacac43'u32, 0xa66262c4'u32, 0xa8919139'u32, 0xa4959531'u32, 0x37e4e4d3'u32, 0x8b7979f2'u32,
      0x32e7e7d5'u32, 0x43c8c88b'u32, 0x5937376e'u32, 0xb76d6dda'u32, 0x8c8d8d01'u32, 0x64d5d5b1'u32, 0xd24e4e9c'u32, 0xe0a9a949'u32,
      0xb46c6cd8'u32, 0xfa5656ac'u32, 0x07f4f4f3'u32, 0x25eaeacf'u32, 0xaf6565ca'u32, 0x8e7a7af4'u32, 0xe9aeae47'u32, 0x18080810'u32,
      0xd5baba6f'u32, 0x887878f0'u32, 0x6f25254a'u32, 0x722e2e5c'u32, 0x241c1c38'u32, 0xf1a6a657'u32, 0xc7b4b473'u32, 0x51c6c697'u32,
      0x23e8e8cb'u32, 0x7cdddda1'u32, 0x9c7474e8'u32, 0x211f1f3e'u32, 0xdd4b4b96'u32, 0xdcbdbd61'u32, 0x868b8b0d'u32, 0x858a8a0f'u32,
      0x907070e0'u32, 0x423e3e7c'u32, 0xc4b5b571'u32, 0xaa6666cc'u32, 0xd8484890'u32, 0x05030306'u32, 0x01f6f6f7'u32, 0x120e0e1c'u32,
      0xa36161c2'u32, 0x5f35356a'u32, 0xf95757ae'u32, 0xd0b9b969'u32, 0x91868617'u32, 0x58c1c199'u32, 0x271d1d3a'u32, 0xb99e9e27'u32,
      0x38e1e1d9'u32, 0x13f8f8eb'u32, 0xb398982b'u32, 0x33111122'u32, 0xbb6969d2'u32, 0x70d9d9a9'u32, 0x898e8e07'u32, 0xa7949433'u32,
      0xb69b9b2d'u32, 0x221e1e3c'u32, 0x92878715'u32, 0x20e9e9c9'u32, 0x49cece87'u32, 0xff5555aa'u32, 0x78282850'u32, 0x7adfdfa5'u32,
      0x8f8c8c03'u32, 0xf8a1a159'u32, 0x80898909'u32, 0x170d0d1a'u32, 0xdabfbf65'u32, 0x31e6e6d7'u32, 0xc6424284'u32, 0xb86868d0'u32,
      0xc3414182'u32, 0xb0999929'u32, 0x772d2d5a'u32, 0x110f0f1e'u32, 0xcbb0b07b'u32, 0xfc5454a8'u32, 0xd6bbbb6d'u32, 0x3a16162c'u32
    ],
    [
      0x6363c6a5'u32, 0x7c7cf884'u32, 0x7777ee99'u32, 0x7b7bf68d'u32, 0xf2f2ff0d'u32, 0x6b6bd6bd'u32, 0x6f6fdeb1'u32, 0xc5c59154'u32,
      0x30306050'u32, 0x01010203'u32, 0x6767cea9'u32, 0x2b2b567d'u32, 0xfefee719'u32, 0xd7d7b562'u32, 0xabab4de6'u32, 0x7676ec9a'u32,
      0xcaca8f45'u32, 0x82821f9d'u32, 0xc9c98940'u32, 0x7d7dfa87'u32, 0xfafaef15'u32, 0x5959b2eb'u32, 0x47478ec9'u32, 0xf0f0fb0b'u32,
      0xadad41ec'u32, 0xd4d4b367'u32, 0xa2a25ffd'u32, 0xafaf45ea'u32, 0x9c9c23bf'u32, 0xa4a453f7'u32, 0x7272e496'u32, 0xc0c09b5b'u32,
      0xb7b775c2'u32, 0xfdfde11c'u32, 0x93933dae'u32, 0x26264c6a'u32, 0x36366c5a'u32, 0x3f3f7e41'u32, 0xf7f7f502'u32, 0xcccc834f'u32,
      0x3434685c'u32, 0xa5a551f4'u32, 0xe5e5d134'u32, 0xf1f1f908'u32, 0x7171e293'u32, 0xd8d8ab73'u32, 0x31316253'u32, 0x15152a3f'u32,
      0x0404080c'u32, 0xc7c79552'u32, 0x23234665'u32, 0xc3c39d5e'u32, 0x18183028'u32, 0x969637a1'u32, 0x05050a0f'u32, 0x9a9a2fb5'u32,
      0x07070e09'u32, 0x12122436'u32, 0x80801b9b'u32, 0xe2e2df3d'u32, 0xebebcd26'u32, 0x27274e69'u32, 0xb2b27fcd'u32, 0x7575ea9f'u32,
      0x0909121b'u32, 0x83831d9e'u32, 0x2c2c5874'u32, 0x1a1a342e'u32, 0x1b1b362d'u32, 0x6e6edcb2'u32, 0x5a5ab4ee'u32, 0xa0a05bfb'u32,
      0x5252a4f6'u32, 0x3b3b764d'u32, 0xd6d6b761'u32, 0xb3b37dce'u32, 0x2929527b'u32, 0xe3e3dd3e'u32, 0x2f2f5e71'u32, 0x84841397'u32,
      0x5353a6f5'u32, 0xd1d1b968'u32, 0x00000000'u32, 0xededc12c'u32, 0x20204060'u32, 0xfcfce31f'u32, 0xb1b179c8'u32, 0x5b5bb6ed'u32,
      0x6a6ad4be'u32, 0xcbcb8d46'u32, 0xbebe67d9'u32, 0x3939724b'u32, 0x4a4a94de'u32, 0x4c4c98d4'u32, 0x5858b0e8'u32, 0xcfcf854a'u32,
      0xd0d0bb6b'u32, 0xefefc52a'u32, 0xaaaa4fe5'u32, 0xfbfbed16'u32, 0x434386c5'u32, 0x4d4d9ad7'u32, 0x33336655'u32, 0x85851194'u32,
      0x45458acf'u32, 0xf9f9e910'u32, 0x02020406'u32, 0x7f7ffe81'u32, 0x5050a0f0'u32, 0x3c3c7844'u32, 0x9f9f25ba'u32, 0xa8a84be3'u32,
      0x5151a2f3'u32, 0xa3a35dfe'u32, 0x404080c0'u32, 0x8f8f058a'u32, 0x92923fad'u32, 0x9d9d21bc'u32, 0x38387048'u32, 0xf5f5f104'u32,
      0xbcbc63df'u32, 0xb6b677c1'u32, 0xdadaaf75'u32, 0x21214263'u32, 0x10102030'u32, 0xffffe51a'u32, 0xf3f3fd0e'u32, 0xd2d2bf6d'u32,
      0xcdcd814c'u32, 0x0c0c1814'u32, 0x13132635'u32, 0xececc32f'u32, 0x5f5fbee1'u32, 0x979735a2'u32, 0x444488cc'u32, 0x17172e39'u32,
      0xc4c49357'u32, 0xa7a755f2'u32, 0x7e7efc82'u32, 0x3d3d7a47'u32, 0x6464c8ac'u32, 0x5d5dbae7'u32, 0x1919322b'u32, 0x7373e695'u32,
      0x6060c0a0'u32, 0x81811998'u32, 0x4f4f9ed1'u32, 0xdcdca37f'u32, 0x22224466'u32, 0x2a2a547e'u32, 0x90903bab'u32, 0x88880b83'u32,
      0x46468cca'u32, 0xeeeec729'u32, 0xb8b86bd3'u32, 0x1414283c'u32, 0xdedea779'u32, 0x5e5ebce2'u32, 0x0b0b161d'u32, 0xdbdbad76'u32,
      0xe0e0db3b'u32, 0x32326456'u32, 0x3a3a744e'u32, 0x0a0a141e'u32, 0x494992db'u32, 0x06060c0a'u32, 0x2424486c'u32, 0x5c5cb8e4'u32,
      0xc2c29f5d'u32, 0xd3d3bd6e'u32, 0xacac43ef'u32, 0x6262c4a6'u32, 0x919139a8'u32, 0x959531a4'u32, 0xe4e4d337'u32, 0x7979f28b'u32,
      0xe7e7d532'u32, 0xc8c88b43'u32, 0x37376e59'u32, 0x6d6ddab7'u32, 0x8d8d018c'u32, 0xd5d5b164'u32, 0x4e4e9cd2'u32, 0xa9a949e0'u32,
      0x6c6cd8b4'u32, 0x5656acfa'u32, 0xf4f4f307'u32, 0xeaeacf25'u32, 0x6565caaf'u32, 0x7a7af48e'u32, 0xaeae47e9'u32, 0x08081018'u32,
      0xbaba6fd5'u32, 0x7878f088'u32, 0x25254a6f'u32, 0x2e2e5c72'u32, 0x1c1c3824'u32, 0xa6a657f1'u32, 0xb4b473c7'u32, 0xc6c69751'u32,
      0xe8e8cb23'u32, 0xdddda17c'u32, 0x7474e89c'u32, 0x1f1f3e21'u32, 0x4b4b96dd'u32, 0xbdbd61dc'u32, 0x8b8b0d86'u32, 0x8a8a0f85'u32,
      0x7070e090'u32, 0x3e3e7c42'u32, 0xb5b571c4'u32, 0x6666ccaa'u32, 0x484890d8'u32, 0x03030605'u32, 0xf6f6f701'u32, 0x0e0e1c12'u32,
      0x6161c2a3'u32, 0x35356a5f'u32, 0x5757aef9'u32, 0xb9b969d0'u32, 0x86861791'u32, 0xc1c19958'u32, 0x1d1d3a27'u32, 0x9e9e27b9'u32,
      0xe1e1d938'u32, 0xf8f8eb13'u32, 0x98982bb3'u32, 0x11112233'u32, 0x6969d2bb'u32, 0xd9d9a970'u32, 0x8e8e0789'u32, 0x949433a7'u32,
      0x9b9b2db6'u32, 0x1e1e3c22'u32, 0x87871592'u32, 0xe9e9c920'u32, 0xcece8749'u32, 0x5555aaff'u32, 0x28285078'u32, 0xdfdfa57a'u32,
      0x8c8c038f'u32, 0xa1a159f8'u32, 0x89890980'u32, 0x0d0d1a17'u32, 0xbfbf65da'u32, 0xe6e6d731'u32, 0x424284c6'u32, 0x6868d0b8'u32,
      0x414182c3'u32, 0x999929b0'u32, 0x2d2d5a77'u32, 0x0f0f1e11'u32, 0xb0b07bcb'u32, 0x5454a8fc'u32, 0xbbbb6dd6'u32, 0x16162c3a'u32
    ],
    [
      0x63c6a563'u32, 0x7cf8847c'u32, 0x77ee9977'u32, 0x7bf68d7b'u32, 0xf2ff0df2'u32, 0x6bd6bd6b'u32, 0x6fdeb16f'u32, 0xc59154c5'u32,
      0x30605030'u32, 0x01020301'u32, 0x67cea967'u32, 0x2b567d2b'u32, 0xfee719fe'u32, 0xd7b562d7'u32, 0xab4de6ab'u32, 0x76ec9a76'u32,
      0xca8f45ca'u32, 0x821f9d82'u32, 0xc98940c9'u32, 0x7dfa877d'u32, 0xfaef15fa'u32, 0x59b2eb59'u32, 0x478ec947'u32, 0xf0fb0bf0'u32,
      0xad41ecad'u32, 0xd4b367d4'u32, 0xa25ffda2'u32, 0xaf45eaaf'u32, 0x9c23bf9c'u32, 0xa453f7a4'u32, 0x72e49672'u32, 0xc09b5bc0'u32,
      0xb775c2b7'u32, 0xfde11cfd'u32, 0x933dae93'u32, 0x264c6a26'u32, 0x366c5a36'u32, 0x3f7e413f'u32, 0xf7f502f7'u32, 0xcc834fcc'u32,
      0x34685c34'u32, 0xa551f4a5'u32, 0xe5d134e5'u32, 0xf1f908f1'u32, 0x71e29371'u32, 0xd8ab73d8'u32, 0x31625331'u32, 0x152a3f15'u32,
      0x04080c04'u32, 0xc79552c7'u32, 0x23466523'u32, 0xc39d5ec3'u32, 0x18302818'u32, 0x9637a196'u32, 0x050a0f05'u32, 0x9a2fb59a'u32,
      0x070e0907'u32, 0x12243612'u32, 0x801b9b80'u32, 0xe2df3de2'u32, 0xebcd26eb'u32, 0x274e6927'u32, 0xb27fcdb2'u32, 0x75ea9f75'u32,
      0x09121b09'u32, 0x831d9e83'u32, 0x2c58742c'u32, 0x1a342e1a'u32, 0x1b362d1b'u32, 0x6edcb26e'u32, 0x5ab4ee5a'u32, 0xa05bfba0'u32,
      0x52a4f652'u32, 0x3b764d3b'u32, 0xd6b761d6'u32, 0xb37dceb3'u32, 0x29527b29'u32, 0xe3dd3ee3'u32, 0x2f5e712f'u32, 0x84139784'u32,
      0x53a6f553'u32, 0xd1b968d1'u32, 0x00000000'u32, 0xedc12ced'u32, 0x20406020'u32, 0xfce31ffc'u32, 0xb179c8b1'u32, 0x5bb6ed5b'u32,
      0x6ad4be6a'u32, 0xcb8d46cb'u32, 0xbe67d9be'u32, 0x39724b39'u32, 0x4a94de4a'u32, 0x4c98d44c'u32, 0x58b0e858'u32, 0xcf854acf'u32,
      0xd0bb6bd0'u32, 0xefc52aef'u32, 0xaa4fe5aa'u32, 0xfbed16fb'u32, 0x4386c543'u32, 0x4d9ad74d'u32, 0x33665533'u32, 0x85119485'u32,
      0x458acf45'u32, 0xf9e910f9'u32, 0x02040602'u32, 0x7ffe817f'u32, 0x50a0f050'u32, 0x3c78443c'u32, 0x9f25ba9f'u32, 0xa84be3a8'u32,
      0x51a2f351'u32, 0xa35dfea3'u32, 0x4080c040'u32, 0x8f058a8f'u32, 0x923fad92'u32, 0x9d21bc9d'u32, 0x38704838'u32, 0xf5f104f5'u32,
      0xbc63dfbc'u32, 0xb677c1b6'u32, 0xdaaf75da'u32, 0x21426321'u32, 0x10203010'u32, 0xffe51aff'u32, 0xf3fd0ef3'u32, 0xd2bf6dd2'u32,
      0xcd814ccd'u32, 0x0c18140c'u32, 0x13263513'u32, 0xecc32fec'u32, 0x5fbee15f'u32, 0x9735a297'u32, 0x4488cc44'u32, 0x172e3917'u32,
      0xc49357c4'u32, 0xa755f2a7'u32, 0x7efc827e'u32, 0x3d7a473d'u32, 0x64c8ac64'u32, 0x5dbae75d'u32, 0x19322b19'u32, 0x73e69573'u32,
      0x60c0a060'u32, 0x81199881'u32, 0x4f9ed14f'u32, 0xdca37fdc'u32, 0x22446622'u32, 0x2a547e2a'u32, 0x903bab90'u32, 0x880b8388'u32,
      0x468cca46'u32, 0xeec729ee'u32, 0xb86bd3b8'u32, 0x14283c14'u32, 0xdea779de'u32, 0x5ebce25e'u32, 0x0b161d0b'u32, 0xdbad76db'u32,
      0xe0db3be0'u32, 0x32645632'u32, 0x3a744e3a'u32, 0x0a141e0a'u32, 0x4992db49'u32, 0x060c0a06'u32, 0x24486c24'u32, 0x5cb8e45c'u32,
      0xc29f5dc2'u32, 0xd3bd6ed3'u32, 0xac43efac'u32, 0x62c4a662'u32, 0x9139a891'u32, 0x9531a495'u32, 0xe4d337e4'u32, 0x79f28b79'u32,
      0xe7d532e7'u32, 0xc88b43c8'u32, 0x376e5937'u32, 0x6ddab76d'u32, 0x8d018c8d'u32, 0xd5b164d5'u32, 0x4e9cd24e'u32, 0xa949e0a9'u32,
      0x6cd8b46c'u32, 0x56acfa56'u32, 0xf4f307f4'u32, 0xeacf25ea'u32, 0x65caaf65'u32, 0x7af48e7a'u32, 0xae47e9ae'u32, 0x08101808'u32,
      0xba6fd5ba'u32, 0x78f08878'u32, 0x254a6f25'u32, 0x2e5c722e'u32, 0x1c38241c'u32, 0xa657f1a6'u32, 0xb473c7b4'u32, 0xc69751c6'u32,
      0xe8cb23e8'u32, 0xdda17cdd'u32, 0x74e89c74'u32, 0x1f3e211f'u32, 0x4b96dd4b'u32, 0xbd61dcbd'u32, 0x8b0d868b'u32, 0x8a0f858a'u32,
      0x70e09070'u32, 0x3e7c423e'u32, 0xb571c4b5'u32, 0x66ccaa66'u32, 0x4890d848'u32, 0x03060503'u32, 0xf6f701f6'u32, 0x0e1c120e'u32,
      0x61c2a361'u32, 0x356a5f35'u32, 0x57aef957'u32, 0xb969d0b9'u32, 0x86179186'u32, 0xc19958c1'u32, 0x1d3a271d'u32, 0x9e27b99e'u32,
      0xe1d938e1'u32, 0xf8eb13f8'u32, 0x982bb398'u32, 0x11223311'u32, 0x69d2bb69'u32, 0xd9a970d9'u32, 0x8e07898e'u32, 0x9433a794'u32,
      0x9b2db69b'u32, 0x1e3c221e'u32, 0x87159287'u32, 0xe9c920e9'u32, 0xce8749ce'u32, 0x55aaff55'u32, 0x28507828'u32, 0xdfa57adf'u32,
      0x8c038f8c'u32, 0xa159f8a1'u32, 0x89098089'u32, 0x0d1a170d'u32, 0xbf65dabf'u32, 0xe6d731e6'u32, 0x4284c642'u32, 0x68d0b868'u32,
      0x4182c341'u32, 0x9929b099'u32, 0x2d5a772d'u32, 0x0f1e110f'u32, 0xb07bcbb0'u32, 0x54a8fc54'u32, 0xbb6dd6bb'u32, 0x162c3a16'u32
    ],
    [
      0xc6a56363'u32, 0xf8847c7c'u32, 0xee997777'u32, 0xf68d7b7b'u32, 0xff0df2f2'u32, 0xd6bd6b6b'u32, 0xdeb16f6f'u32, 0x9154c5c5'u32,
      0x60503030'u32, 0x02030101'u32, 0xcea96767'u32, 0x567d2b2b'u32, 0xe719fefe'u32, 0xb562d7d7'u32, 0x4de6abab'u32, 0xec9a7676'u32,
      0x8f45caca'u32, 0x1f9d8282'u32, 0x8940c9c9'u32, 0xfa877d7d'u32, 0xef15fafa'u32, 0xb2eb5959'u32, 0x8ec94747'u32, 0xfb0bf0f0'u32,
      0x41ecadad'u32, 0xb367d4d4'u32, 0x5ffda2a2'u32, 0x45eaafaf'u32, 0x23bf9c9c'u32, 0x53f7a4a4'u32, 0xe4967272'u32, 0x9b5bc0c0'u32,
      0x75c2b7b7'u32, 0xe11cfdfd'u32, 0x3dae9393'u32, 0x4c6a2626'u32, 0x6c5a3636'u32, 0x7e413f3f'u32, 0xf502f7f7'u32, 0x834fcccc'u32,
      0x685c3434'u32, 0x51f4a5a5'u32, 0xd134e5e5'u32, 0xf908f1f1'u32, 0xe2937171'u32, 0xab73d8d8'u32, 0x62533131'u32, 0x2a3f1515'u32,
      0x080c0404'u32, 0x9552c7c7'u32, 0x46652323'u32, 0x9d5ec3c3'u32, 0x30281818'u32, 0x37a19696'u32, 0x0a0f0505'u32, 0x2fb59a9a'u32,
      0x0e090707'u32, 0x24361212'u32, 0x1b9b8080'u32, 0xdf3de2e2'u32, 0xcd26ebeb'u32, 0x4e692727'u32, 0x7fcdb2b2'u32, 0xea9f7575'u32,
      0x121b0909'u32, 0x1d9e8383'u32, 0x58742c2c'u32, 0x342e1a1a'u32, 0x362d1b1b'u32, 0xdcb26e6e'u32, 0xb4ee5a5a'u32, 0x5bfba0a0'u32,
      0xa4f65252'u32, 0x764d3b3b'u32, 0xb761d6d6'u32, 0x7dceb3b3'u32, 0x527b2929'u32, 0xdd3ee3e3'u32, 0x5e712f2f'u32, 0x13978484'u32,
      0xa6f55353'u32, 0xb968d1d1'u32, 0x00000000'u32, 0xc12ceded'u32, 0x40602020'u32, 0xe31ffcfc'u32, 0x79c8b1b1'u32, 0xb6ed5b5b'u32,
      0xd4be6a6a'u32, 0x8d46cbcb'u32, 0x67d9bebe'u32, 0x724b3939'u32, 0x94de4a4a'u32, 0x98d44c4c'u32, 0xb0e85858'u32, 0x854acfcf'u32,
      0xbb6bd0d0'u32, 0xc52aefef'u32, 0x4fe5aaaa'u32, 0xed16fbfb'u32, 0x86c54343'u32, 0x9ad74d4d'u32, 0x66553333'u32, 0x11948585'u32,
      0x8acf4545'u32, 0xe910f9f9'u32, 0x04060202'u32, 0xfe817f7f'u32, 0xa0f05050'u32, 0x78443c3c'u32, 0x25ba9f9f'u32, 0x4be3a8a8'u32,
      0xa2f35151'u32, 0x5dfea3a3'u32, 0x80c04040'u32, 0x058a8f8f'u32, 0x3fad9292'u32, 0x21bc9d9d'u32, 0x70483838'u32, 0xf104f5f5'u32,
      0x63dfbcbc'u32, 0x77c1b6b6'u32, 0xaf75dada'u32, 0x42632121'u32, 0x20301010'u32, 0xe51affff'u32, 0xfd0ef3f3'u32, 0xbf6dd2d2'u32,
      0x814ccdcd'u32, 0x18140c0c'u32, 0x26351313'u32, 0xc32fecec'u32, 0xbee15f5f'u32, 0x35a29797'u32, 0x88cc4444'u32, 0x2e391717'u32,
      0x9357c4c4'u32, 0x55f2a7a7'u32, 0xfc827e7e'u32, 0x7a473d3d'u32, 0xc8ac6464'u32, 0xbae75d5d'u32, 0x322b1919'u32, 0xe6957373'u32,
      0xc0a06060'u32, 0x19988181'u32, 0x9ed14f4f'u32, 0xa37fdcdc'u32, 0x44662222'u32, 0x547e2a2a'u32, 0x3bab9090'u32, 0x0b838888'u32,
      0x8cca4646'u32, 0xc729eeee'u32, 0x6bd3b8b8'u32, 0x283c1414'u32, 0xa779dede'u32, 0xbce25e5e'u32, 0x161d0b0b'u32, 0xad76dbdb'u32,
      0xdb3be0e0'u32, 0x64563232'u32, 0x744e3a3a'u32, 0x141e0a0a'u32, 0x92db4949'u32, 0x0c0a0606'u32, 0x486c2424'u32, 0xb8e45c5c'u32,
      0x9f5dc2c2'u32, 0xbd6ed3d3'u32, 0x43efacac'u32, 0xc4a66262'u32, 0x39a89191'u32, 0x31a49595'u32, 0xd337e4e4'u32, 0xf28b7979'u32,
      0xd532e7e7'u32, 0x8b43c8c8'u32, 0x6e593737'u32, 0xdab76d6d'u32, 0x018c8d8d'u32, 0xb164d5d5'u32, 0x9cd24e4e'u32, 0x49e0a9a9'u32,
      0xd8b46c6c'u32, 0xacfa5656'u32, 0xf307f4f4'u32, 0xcf25eaea'u32, 0xcaaf6565'u32, 0xf48e7a7a'u32, 0x47e9aeae'u32, 0x10180808'u32,
      0x6fd5baba'u32, 0xf0887878'u32, 0x4a6f2525'u32, 0x5c722e2e'u32, 0x38241c1c'u32, 0x57f1a6a6'u32, 0x73c7b4b4'u32, 0x9751c6c6'u32,
      0xcb23e8e8'u32, 0xa17cdddd'u32, 0xe89c7474'u32, 0x3e211f1f'u32, 0x96dd4b4b'u32, 0x61dcbdbd'u32, 0x0d868b8b'u32, 0x0f858a8a'u32,
      0xe0907070'u32, 0x7c423e3e'u32, 0x71c4b5b5'u32, 0xccaa6666'u32, 0x90d84848'u32, 0x06050303'u32, 0xf701f6f6'u32, 0x1c120e0e'u32,
      0xc2a36161'u32, 0x6a5f3535'u32, 0xaef95757'u32, 0x69d0b9b9'u32, 0x17918686'u32, 0x9958c1c1'u32, 0x3a271d1d'u32, 0x27b99e9e'u32,
      0xd938e1e1'u32, 0xeb13f8f8'u32, 0x2bb39898'u32, 0x22331111'u32, 0xd2bb6969'u32, 0xa970d9d9'u32, 0x07898e8e'u32, 0x33a79494'u32,
      0x2db69b9b'u32, 0x3c221e1e'u32, 0x15928787'u32, 0xc920e9e9'u32, 0x8749cece'u32, 0xaaff5555'u32, 0x50782828'u32, 0xa57adfdf'u32,
      0x038f8c8c'u32, 0x59f8a1a1'u32, 0x09808989'u32, 0x1a170d0d'u32, 0x65dabfbf'u32, 0xd731e6e6'u32, 0x84c64242'u32, 0xd0b86868'u32,
      0x82c34141'u32, 0x29b09999'u32, 0x5a772d2d'u32, 0x1e110f0f'u32, 0x7bcbb0b0'u32, 0xa8fc5454'u32, 0x6dd6bbbb'u32, 0x2c3a1616'u32
    ]
  ]

  ECHO224_HASH_SIZE*: int = 28
  ECHO256_HASH_SIZE*: int = 32
  ECHO384_HASH_SIZE*: int = 48
  ECHO512_HASH_SIZE*: int = 64

  FIRST_BITS = 0xFEFEFEFEFEFEFEFE'u64
  LAST_BITS   = 0x0101010101010101'u64

  EMPTY_SALT: array[16, uint8] = [0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8]

template blockSize*(hashSize: static int): static int =
  static: doAssert (hashSize == 28) or (hashSize == 32) or (hashSize == 48) or (hashSize == 64)
  when hashSize == 28:
    192
  elif hashSize == 32:
    192
  elif hashSize == 48:
    128
  elif hashSize == 64:
    128
  else:
    0

type
  ECHOCtx*[hashSize: static int] = object
    state*: array[32, uint64]
    buffer*: array[blockSize(hashSize), uint8]
    index*: int
    length*: uint64
    salt*: array[2, uint64]

  ECHO224Ctx* = ECHOCtx[ECHO224_HASH_SIZE]
  ECHO256Ctx* = ECHOCtx[ECHO256_HASH_SIZE]
  ECHO384Ctx* = ECHOCtx[ECHO384_HASH_SIZE]
  ECHO512Ctx* = ECHOCtx[ECHO512_HASH_SIZE]

template hashSize*[N: static int](ctx: ECHOCtx[N]): static int =
  N

template blockSize*[N: static int](ctx: ECHOCtx[N]): static int =
  blockSize(N)

template echoTransform[K, B: static int](ctx: var EchoCtx[K], chunk: slicearray[B, uint8], addedBits: static bool, addToTotal: uint64): void =
  var counter: uint64 = 0'u64
  when addedBits:
    counter = ctx.length + addToTotal

  var temp: array[B div 8, uint64]
  decodeLE(chunk.toSliceArray(0, B - 1), temp.toSliceArray(0, B div 8 - 1))
  const start: int = 32 - temp.len
  for i in static(0 ..< temp.len):
    ctx.state[start + i] = temp[i]

  var w = ctx.state
  const rounds: int = when K > 32: 10 else: 8

  var temp0, temp1, temp2, temp3, c0, c1: uint32

  for _ in static(0 ..< rounds):
    for r in static(0 ..< 16):
      let index0 = r * 2
      let index1 = r * 2 + 1
      c0 = uint32(counter and 0xFFFFFFFF'u64)
      c1 = uint32((counter shr 32) and 0xFFFFFFFF'u64)

      temp0 = c0 xor Table[0][int(w[index0] and 0xFF'u64)] xor
                     Table[1][int((w[index0] shr 40) and 0xFF'u64)] xor
                     Table[2][int((w[index1] shr 16) and 0xFF'u64)] xor
                     Table[3][int((w[index1] shr 56) and 0xFF'u64)]
      temp1 = c1 xor Table[0][int((w[index0] shr 32) and 0xFF'u64)] xor
                     Table[1][int((w[index1] shr  8) and 0xFF'u64)] xor
                     Table[2][int((w[index1] shr 48) and 0xFF'u64)] xor
                     Table[3][int((w[index0] shr 24) and 0xFF'u64)]
      temp2 = Table[0][int(w[index1] and 0xFF'u64)] xor
              Table[1][int((w[index1] shr 40) and 0xFF'u64)] xor
              Table[2][int((w[index0] shr 16) and 0xFF'u64)] xor
              Table[3][int((w[index0] shr 56) and 0xFF'u64)]
      temp3 = Table[0][int((w[index1] shr 32) and 0xFF'u64)] xor
              Table[1][int((w[index0] shr  8) and 0xFF'u64)] xor
              Table[2][int((w[index0] shr 48) and 0xFF'u64)] xor
              Table[3][int((w[index1] shr 24) and 0xFF'u64)]

      counter.inc

      let lo0 = Table[0][int(temp0          and 0xFF'u32)] xor
                Table[1][int((temp1 shr  8) and 0xFF'u32)] xor
                Table[2][int((temp2 shr 16) and 0xFF'u32)] xor
                Table[3][int((temp3 shr 24) and 0xFF'u32)]
      let hi0 = Table[0][int(temp1          and 0xFF'u32)] xor
                Table[1][int((temp2 shr  8) and 0xFF'u32)] xor
                Table[2][int((temp3 shr 16) and 0xFF'u32)] xor
                Table[3][int((temp0 shr 24) and 0xFF'u32)]

      let lo1 = Table[0][int(temp2          and 0xFF'u32)] xor
                Table[1][int((temp3 shr  8) and 0xFF'u32)] xor
                Table[2][int((temp0 shr 16) and 0xFF'u32)] xor
                Table[3][int((temp1 shr 24) and 0xFF'u32)]

      let hi1 = Table[0][int(temp3          and 0xFF'u32)] xor
                Table[1][int((temp0 shr  8) and 0xFF'u32)] xor
                Table[2][int((temp1 shr 16) and 0xFF'u32)] xor
                Table[3][int((temp2 shr 24) and 0xFF'u32)]

      w[index0] = uint64(lo0) xor (uint64(hi0) shl 32) xor ctx.salt[0]
      w[index1] = uint64(lo1) xor (uint64(hi1) shl 32) xor ctx.salt[1]

    swap(w[2], w[10])
    swap(w[3], w[11])
    swap(w[4], w[20])
    swap(w[5], w[21])
    swap(w[6], w[30])
    swap(w[7], w[31])
    swap(w[12], w[28])
    swap(w[13], w[29])
    swap(w[22], w[14])
    swap(w[23], w[15])
    swap(w[30], w[14])
    swap(w[31], w[15])
    swap(w[26], w[18])
    swap(w[27], w[19])
    swap(w[26], w[10])
    swap(w[27], w[11])

    for i in static(0 ..< 4):
      for j in static(0 ..< 2):
        let index: int = i * 8 + j
        let a = w[index]
        let b = w[index + 2]
        let c = w[index + 4]
        let d = w[index + 6]
        let dblA = ((a shl 1) and FIRST_BITS) xor (((a shr 7) and LAST_BITS) * 0x1b'u64)
        let dblB = ((b shl 1) and FIRST_BITS) xor (((b shr 7) and LAST_BITS) * 0x1b'u64)
        let dblC = ((c shl 1) and FIRST_BITS) xor (((c shr 7) and LAST_BITS) * 0x1b'u64)
        let dblD = ((d shl 1) and FIRST_BITS) xor (((d shr 7) and LAST_BITS) * 0x1b'u64)
        w[index] = dblA xor dblB xor b xor c xor d
        w[index + 2] = dblB xor dblC xor c xor d xor a
        w[index + 4] = dblC xor dblD xor d xor a xor b
        w[index + 6] = dblD xor dblA xor a xor b xor c

  when K <= 32:
    for i in static(0 ..< 8):
      ctx.state[i] = ctx.state[i] xor ctx.state[i + 8] xor ctx.state[i + 16] xor ctx.state[i + 24] xor w[i] xor w[i + 8] xor w[i + 16] xor w[i + 24]
  else:
    for i in static(0 ..< 16):
      ctx.state[i] = ctx.state[i] xor ctx.state[i + 16] xor w[i] xor w[i + 16]

template echoInitC[K: static int](ctx: var EchoCtx[K], saltInput: array[16, uint8] = EMPTY_SALT): void =
  zeroMem(addr ctx.state[0], 256)
  zeroMem(addr ctx.buffer[0], blockSize(K))
  const roundsState = when K > 32: 8 else: 4
  for i in static(0 ..< roundsState):
    ctx.state[2 * i] = uint64(K * 8)
    ctx.state[2 * i + 1] = 0'u64
  ctx.index = 0
  ctx.length = 0'u64
  decodeLE(saltInput, ctx.salt)

template echoInputC[K: static int](ctx: var EchoCtx[K], input: openArray[uint8]): void =
  # set inputLen
  let inputLen: int = input.len

  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    const blockSize: int = blockSize(K)
    # set index and add length
    var index: int = ctx.index
    # ctx.length += uint64(inputLen)

    let left: int = blockSize - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      echoTransform(ctx, ctx.buffer.toSliceArray(0, blockSize - 1), true, uint64(left) shl 3)
      ctx.length += uint64(left) shl 3
      position = left
      index = 0

      while position + blockSize <= inputLen:
        echoTransform(ctx, input.toSliceArray(position, position + blockSize - 1, blockSize), true, uint64(blockSize) shl 3)
        position += blockSize
        ctx.length += uint64(blockSize) shl 3

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain
      ctx.length += uint64(remain) shl 3

    ctx.index = index

template echoFinalC[K: static int](ctx: var EchoCtx[K]): array[K, uint8] =
  var output: array[K, uint8]

  var index: int = ctx.index

  ctx.buffer[index] = 0x80'u8
  index.inc

  const blockSize: int = blockSize(K)

  let padLen: int = if index <= blockSize - 18: blockSize - 18 - index else: blockSize - index

  if index <= blockSize - 18:
    zeroMem(addr ctx.buffer[index], padLen)
  else:
    if padLen > 0:
      zeroMem(addr ctx.buffer[index], padLen)
    echoTransform(ctx, ctx.buffer.toSliceArray(0, blockSize - 1), true, 0'u64)
    zeroMem(addr ctx.buffer[0], blockSize - 18)
    index = 0

  let hashSize: uint16 = uint16(K) * 8'u16
  toBytesLE(hashSize, ctx.buffer.toSliceArray(blockSize - 18, blockSize - 17))
  toBytesLE(ctx.length, ctx.buffer.toSliceArray(blockSize - 16, blockSize - 9))
  zeroMem(addr ctx.buffer[blockSize - 8], 8)

  if index > 1:
    echoTransform(ctx, ctx.buffer.toSliceArray(0, blockSize - 1), true, 0'u64)
  else:
    echoTransform(ctx, ctx.buffer.toSliceArray(0, blockSize - 1), false, 0'u64)

  when LE:
    copyMem(addr output[0], addr ctx.state[0], K)
  else:
    when K == 28:
      var temp: array[32, uint8]
      encodeLE(ctx.state.toSliceArray(0, 3), temp.toSliceArray(0, 31))
      copyMem(addr output, addr temp, 28)
    elif K == 32:
      encodeLE(ctx.state.toSliceArray(0, 3), output.toSliceArray(0, 31))
    elif K == 48:
      encodeLE(ctx.state.toSliceArray(0, 5), output.toSliceArray(0, 47))
    elif K == 64:
      encodeLE(ctx.state.toSliceArray(0, 7), output.toSliceArray(0, 63))

  output

# export wrappers
when defined(templateOpt):
  # === ECHO 224 ===
  template echo224Init*(ctx: var ECHO224Ctx): void = echoInitC(ctx)
  template echo224Input*(ctx: var ECHO224Ctx, input: openArray[uint8]): void = echoInputC(ctx, input)
  template echo224Final*(ctx: var ECHO224Ctx): array[28, uint8] = echoFinalC(ctx)

  # === ECHO 256 ===
  template echo256Init*(ctx: var ECHO256Ctx): void = echoInitC(ctx)
  template echo256Input*(ctx: var ECHO256Ctx, input: openArray[uint8]): void = echoInputC(ctx, input)
  template echo256Final*(ctx: var ECHO256Ctx): array[32, uint8] = echoFinalC(ctx)

  # === ECHO 384 ===
  template echo384Init*(ctx: var ECHO384Ctx): void = echoInitC(ctx)
  template echo384Input*(ctx: var ECHO384Ctx, input: openArray[uint8]): void = echoInputC(ctx, input)
  template echo384Final*(ctx: var ECHO384Ctx): array[48, uint8] = echoFinalC(ctx)

  # === ECHO 512 ===
  template echo512Init*(ctx: var ECHO512Ctx): void = echoInitC(ctx)
  template echo512Input*(ctx: var ECHO512Ctx, input: openArray[uint8]): void = echoInputC(ctx, input)
  template echo512Final*(ctx: var ECHO512Ctx): array[64, uint8] = echoFinalC(ctx)

  when Native:
    template echo224Init*(ctx: ptr ECHO224Ctx): void = echoInitC(ctx[])
    template echo224Input*(ctx: ptr ECHO224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template echo224Final*(ctx: ptr ECHO224Ctx, output: ptr array[28, uint8]): void = output[] = echoFinalC(ctx[])

    template echo256Init*(ctx: ptr ECHO256Ctx): void = echoInitC(ctx[])
    template echo256Input*(ctx: ptr ECHO256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template echo256Final*(ctx: ptr ECHO256Ctx, output: ptr array[32, uint8]): void = output[] = echoFinalC(ctx[])

    template echo384Init*(ctx: ptr ECHO384Ctx): void = echoInitC(ctx[])
    template echo384Input*(ctx: ptr ECHO384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template echo384Final*(ctx: ptr ECHO384Ctx, output: ptr array[48, uint8]): void = output[] = echoFinalC(ctx[])

    template echo512Init*(ctx: ptr ECHO512Ctx): void = echoInitC(ctx[])
    template echo512Input*(ctx: ptr ECHO512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template echo512Final*(ctx: ptr ECHO512Ctx, output: ptr array[64, uint8]): void = output[] = echoFinalC(ctx[])

else:
  when Native:
    proc echo224Init*(ctx: var ECHO224Ctx): void = echoInitC(ctx)
    proc echo224Input*(ctx: var ECHO224Ctx, input: openArray[uint8]): void = echoInputC(ctx, input)
    proc echo224Final*(ctx: var ECHO224Ctx): array[28, uint8] = echoFinalC(ctx)

    proc echo256Init*(ctx: var ECHO256Ctx): void = echoInitC(ctx)
    proc echo256Input*(ctx: var ECHO256Ctx, input: openArray[uint8]): void = echoInputC(ctx, input)
    proc echo256Final*(ctx: var ECHO256Ctx): array[32, uint8] = echoFinalC(ctx)

    proc echo384Init*(ctx: var ECHO384Ctx): void = echoInitC(ctx)
    proc echo384Input*(ctx: var ECHO384Ctx, input: openArray[uint8]): void = echoInputC(ctx, input)
    proc echo384Final*(ctx: var ECHO384Ctx): array[48, uint8] = echoFinalC(ctx)

    proc echo512Init*(ctx: var ECHO512Ctx): void = echoInitC(ctx)
    proc echo512Input*(ctx: var ECHO512Ctx, input: openArray[uint8]): void = echoInputC(ctx, input)
    proc echo512Final*(ctx: var ECHO512Ctx): array[64, uint8] = echoFinalC(ctx)

  when defined(c) or defined(objc):
    proc echo224Init*(ctx: ptr ECHO224Ctx): void {.exportc: "echo224Init".} = echoInitC(ctx[])
    proc echo224Input*(ctx: ptr ECHO224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "echo224Input".} = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc echo224Final*(ctx: ptr ECHO224Ctx, output: ptr array[28, uint8]): void {.exportc: "echo224Final".} = output[] = echoFinalC(ctx[])

    proc echo256Init*(ctx: ptr ECHO256Ctx): void {.exportc: "echo256Init".} = echoInitC(ctx[])
    proc echo256Input*(ctx: ptr ECHO256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "echo256Input".} = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc echo256Final*(ctx: ptr ECHO256Ctx, output: ptr array[32, uint8]): void {.exportc: "echo256Final".} = output[] = echoFinalC(ctx[])

    proc echo384Init*(ctx: ptr ECHO384Ctx): void {.exportc: "echo384Init".} = echoInitC(ctx[])
    proc echo384Input*(ctx: ptr ECHO384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "echo384Input".} = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc echo384Final*(ctx: ptr ECHO384Ctx, output: ptr array[48, uint8]): void {.exportc: "echo384Final".} = output[] = echoFinalC(ctx[])

    proc echo512Init*(ctx: ptr ECHO512Ctx): void {.exportc: "echo512Init".} = echoInitC(ctx[])
    proc echo512Input*(ctx: ptr ECHO512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "echo512Input".} = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc echo512Final*(ctx: ptr ECHO512Ctx, output: ptr array[64, uint8]): void {.exportc: "echo512Final".} = output[] = echoFinalC(ctx[])

  elif defined(cpp):
    proc echo224Init*(ctx: ptr ECHO224Ctx): void {.exportcpp: "echo224Init".} = echoInitC(ctx[])
    proc echo224Input*(ctx: ptr ECHO224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "echo224Input".} = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc echo224Final*(ctx: ptr ECHO224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "echo224Final".} = output[] = echoFinalC(ctx[])

    proc echo256Init*(ctx: ptr ECHO256Ctx): void {.exportcpp: "echo256Init".} = echoInitC(ctx[])
    proc echo256Input*(ctx: ptr ECHO256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "echo256Input".} = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc echo256Final*(ctx: ptr ECHO256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "echo256Final".} = output[] = echoFinalC(ctx[])

    proc echo384Init*(ctx: ptr ECHO384Ctx): void {.exportcpp: "echo384Init".} = echoInitC(ctx[])
    proc echo384Input*(ctx: ptr ECHO384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "echo384Input".} = echoInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc echo384Final*(ctx: ptr ECHO384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "echo384Final".} = output[] = echoFinalC(ctx[])

    proc echo512Init*(ctx: ptr ECHO512Ctx): void {.exportcpp: "echo512Init".} = echoInitC(ctx[])
    proc echo512Input*(ctx: ptr ECHO512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "echo512Input".} = echoInitC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc echo512Final*(ctx: ptr ECHO512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "echo512Final".} = output[] = echoFinalC(ctx[])
