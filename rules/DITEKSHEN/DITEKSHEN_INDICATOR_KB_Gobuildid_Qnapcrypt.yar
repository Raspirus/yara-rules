rule DITEKSHEN_INDICATOR_KB_Gobuildid_Qnapcrypt : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "4cdea15f-d8fd-5720-ba25-eb60e9b0f9ce"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1590-L1598"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "b3ee583c395701350c091041a72f988d1b5ae607b642b42152fcda29f9be63e2"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"XcBqbQohm7UevdYNABvs/2RcJz1616naXSRu2xvTX/b6F3Jt1-5WAIexSyzeun/MpHqs5fJA5G2D9gVuUCe\"" ascii

	condition:
		uint16(0)==0x5a4d and filesize <8000KB and 1 of them
}