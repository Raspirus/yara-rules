
rule DITEKSHEN_INDICATOR_KB_Gobuildid_Banload : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "5955afd5-f26f-5df1-b355-b8f168b694b0"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1635-L1643"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "534de1ce161e5e27f380f96b83630aa75031f268658aa7e8ff8ecce82ed5d4cd"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"a3629ee6ab610a57f242f59a3dd5e5f6de73da40\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}