import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_Azbelt : FILE
{
	meta:
		description = "Detects azbelt for enumerating Azure related credentials primarily on AAD joined machines"
		author = "ditekSHen"
		id = "cf9268d2-1928-51e8-9643-ee0a5bada9fa"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1323-L1338"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "71cc2b3418ea5e285adafe03fa80bade67dc3e4073fe58d42bc6190860b48b43"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "@http://169.254.169.254/metadata/identity/oauth2/token?api-version=" ascii
		$s2 = "@Partner Customer Delegated Admin Offline Processor" fullword ascii
		$s3 = "@TargetName: " fullword ascii
		$s4 = "httpclient.nim" fullword ascii
		$s5 = "@DSREG_DEVICE_JOIN" fullword ascii
		$s6 = "@.azure/msal_token_cache.bin" fullword ascii
		$s7 = "CredEnumerateW" fullword ascii
		$s8 = "@http://169.254.169.254/metadata/instance?api-version=" ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}