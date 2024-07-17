
rule DITEKSHEN_INDICATOR_KB_Gobuildid_Gostealer : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "25c0eb8b-c69c-5f50-b622-daaa3c8c62a4"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1552-L1562"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "d548bc2580c8e8233a5fcdf85b947547c10f2c4d0056d14e990f30dd7b9a0672"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"xQV-b1Fr7d576TTTpbXi/gq4FgVQqMcg--9tmY13y/76rKNEUBENlDFDcecmm_/mbw17A_6WrROaNCYDEQF\"" ascii
		$s2 = "Go build ID: \"x4VqrSSsx8iysxVdfB-z/gIF3p7SUxiZsVgTuq7bN/93XHuILGnGYq2L83fRpj/eoY6nTqwk1sdMHTaXzlw\"" ascii
		$s3 = "Go build ID: \"BPRThIYWbHcZQQ4K1y2t/2mO0-FjLC50P0QZuMTgC/9i6TYw_akiEF9ZPN0s3p/s1XoqXr7EyXMDVw5TTP3\"" ascii

	condition:
		uint16(0)==0x5a4d and filesize <8000KB and 1 of them
}