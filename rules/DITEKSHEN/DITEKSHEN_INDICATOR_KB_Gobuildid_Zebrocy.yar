
rule DITEKSHEN_INDICATOR_KB_Gobuildid_Zebrocy : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "fc805e9d-47a0-5fcb-9b21-4806c13ab7b4"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1541-L1550"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "16b88460896012b42ca576995f5de98a7a9d2fcc53f8e148427bca31a883d19b"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"l6RAKXh3Wg1yzn63nita/b2_Y0DGY05NFWuZ_4gUT/H91sCRktnyyYVzECfvvA/l8f-yII0L_miSjIe-VQu\"" ascii
		$s2 = "Go build ID: \"fiGGvLVFcvIhuJsSaail/jLt9TEPQiusg7IpRkp4H/hlcoXZIfsl1D4521LqEL/yL8dN86mCNc39WqQTgGn\"" ascii

	condition:
		uint16(0)==0x5a4d and filesize <8000KB and 1 of them
}