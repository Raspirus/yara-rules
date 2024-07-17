
rule DITEKSHEN_INDICATOR_XML_Legacydrawing_Autoload_Document : FILE
{
	meta:
		description = "detects AutoLoad documents using LegacyDrawing"
		author = "ditekSHen"
		id = "ce116601-7048-5a3f-9b73-5127ca3b359e"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L559-L569"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "a038636f5e8e7837c2209072f1659b921c8a9a48d4ed153e735915cf1f7f3fcc"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "<legacyDrawing r:id=\"" ascii
		$s2 = "<oleObject progId=\"" ascii
		$s3 = "autoLoad=\"true\"" ascii

	condition:
		uint32(0)==0x6d783f3c and all of ($s*)
}