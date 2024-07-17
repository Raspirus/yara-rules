
rule DITEKSHEN_INDICATOR_KB_Gobuildid_Hive : FILE
{
	meta:
		description = "Detects Golang Build IDs in Hive ransomware"
		author = "ditekSHen"
		id = "7d7f7757-de7b-52a7-aab0-8fda38a86fd1"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1645-L1653"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f311a3661ea3a26ebca6cd283d1e219011acfdfbb13fa8b919ca2724b9f4aae7"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"XDub7DGmWVQ2COC6W4If/XHMqRPf2lnJUiVkG1CR6/u_MaUU0go2UUmLb_INuv/WrZSyz-WMW1st_NaM935\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}