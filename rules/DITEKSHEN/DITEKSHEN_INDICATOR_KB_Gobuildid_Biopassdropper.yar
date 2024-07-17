rule DITEKSHEN_INDICATOR_KB_Gobuildid_Biopassdropper : FILE
{
	meta:
		description = "Detects Golang Build IDs in BioPass dropper"
		author = "ditekSHen"
		id = "b82d34d9-7774-5f99-9d76-b5426e015981"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1678-L1686"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "3b586e886b9f901dde1c73aa07ce0d45e4ff417459f298094359ec1c1e02e522"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"OS0VlkdEIlcl3WDDr9Za/_oVwEipaaX6V4mEEYg2V/PytlyeIYgV65maz4wT2Y/IQvgbHv3bbLV42i10qq2\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}