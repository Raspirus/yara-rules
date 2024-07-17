rule DITEKSHEN_INDICATOR_TOOL_PWS_Keychaindumper : FILE
{
	meta:
		description = "Detects macOS certificate/password keychain dumping tool"
		author = "ditekSHen"
		id = "cec094fa-c651-58a6-a306-f16d8603e536"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L473-L484"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f606bdd5dba2180ffc552c46373b52801a0bd65a538b381fb9f4240efc5bd458"
		score = 75
		quality = 71
		tags = "FILE"
		clamav_sig = "INDICATOR_Osx.Tool.PWS.KeychainDumper"

	strings:
		$s1 = "_getEmptyKeychainItemString" fullword ascii
		$s2 = "NdumpKeychainEntitlements" fullword ascii
		$s3 = "_dumpKeychainEntitlements" fullword ascii

	condition:
		( uint16(0)==0xfeca or uint16(0)==0xfacf) and all of them
}