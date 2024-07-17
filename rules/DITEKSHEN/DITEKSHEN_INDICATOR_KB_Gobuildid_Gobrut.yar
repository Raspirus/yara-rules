
rule DITEKSHEN_INDICATOR_KB_Gobuildid_Gobrut : FILE
{
	meta:
		description = "Detects Golang Build IDs in GoBrut"
		author = "ditekSHen"
		id = "65953012-fc84-50d0-b769-64df66d8a54b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1668-L1676"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "40c305f019cb31222fa75a24315764cb5e5356afaa72aefb59916d615a8fca28"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"sf_2_ylcjquGBe4mQ99L/aPvdLbM2z9HfoDN3RazG/8bhYeVA67N-ifbDYCDJe/UZzCu_EFL9f10gSfO4L0\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}