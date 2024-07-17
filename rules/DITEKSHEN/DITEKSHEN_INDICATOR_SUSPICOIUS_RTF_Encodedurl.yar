
rule DITEKSHEN_INDICATOR_SUSPICOIUS_RTF_Encodedurl : FILE
{
	meta:
		description = "Detects executables calling ClearMyTracksByProcess"
		author = "ditekSHen"
		id = "6b3f0434-24b2-5ae8-a6fc-c0fdded4996f"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L905-L916"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "cb791bb5e2af46ff9f1f07cef33bbd51edc44b2394d6f3eff31d39eaa5ff2a33"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "\\u-65431?\\u-65419?\\u-65419?\\u-65423?\\u-" ascii wide
		$s2 = "\\u-65432?\\u-65420?\\u-65420?\\u-65424?\\u-" ascii wide
		$s3 = "\\u-65433?\\u-65430?\\u-65427?\\u-65434?\\u-" ascii wide
		$s4 = "\\u-65434?\\u-65431?\\u-65428?\\u-65435?\\u-" ascii wide

	condition:
		uint32(0)==0x74725c7b and any of them
}