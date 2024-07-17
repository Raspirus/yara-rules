rule DITEKSHEN_INDICATOR_TOOL_PET_Mulit_Venomagent : FILE
{
	meta:
		description = "Detects Venom Proxy Agent"
		author = "ditekSHen"
		id = "598bc773-cbe9-503b-ba3e-27c2cde8910d"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L633-L645"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "5eda23a237404a44dc9eb057adbf6106166374168eb08e55c182da5c05ecb4f1"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "github.com/Dliv3/Venom/" ascii
		$s2 = "3HpKQVB3nT3qaNQPT-ZU/SKJ55ofz5TEmg5O3ROWA/CUs_-gfa04tGVO633Z4G/OSeEpRRb0Sq_5R6ArIi-" ascii
		$s3 = "venom_agent -" ascii
		$s4 = "bufferssh-userauthtransmitfileunknown portwirep: p->m= != sweepgen" ascii
		$s5 = "golang.org/x/crypto/ssh.(*handshakeTransport).readPacket"

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f or uint16(0)==0xfacf) and 3 of them
}