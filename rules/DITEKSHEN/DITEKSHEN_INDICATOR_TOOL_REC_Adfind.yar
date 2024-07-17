rule DITEKSHEN_INDICATOR_TOOL_REC_Adfind : FILE
{
	meta:
		description = "Detect ADFind"
		author = "ditekSHen"
		id = "2f0d02a1-7488-5645-aa08-1eadee2862e8"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L963-L974"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "41fb9f72032f76adc6f1fccd25a1364f153eb2430063e9d582f3dcd9fc9ac84a"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "\\AdFind\\AdFind\\AdFind.h" ascii
		$s2 = "\\AdFind\\AdFind\\AdFind.cpp" ascii
		$s3 = "\\AdFind\\Release\\AdFind.pdb" ascii
		$s4 = "joeware_default_adfind.cf" ascii

	condition:
		uint16(0)==0x5a4d and 2 of them
}