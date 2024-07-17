rule DITEKSHEN_INDICATOR_TOOLS_Rsockstun : FILE
{
	meta:
		description = "Detects rsockstun"
		author = "ditekShen"
		id = "a284a607-abea-5914-ad3a-84eaff733ee0"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1833-L1845"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "4ad0ac389bf8961b0dd987a72d5dd534e5e3cc673f0e07aa49d39d1fd3f5f53e"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "main.connectviaproxy" ascii
		$s2 = "main.connectForSocks" ascii
		$s3 = "main.listenForClients" ascii
		$s4 = "main.listenForSocks" ascii
		$s5 = "Proxy-Authorization: NTLM TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA=" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and all of them
}