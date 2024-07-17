
rule DITEKSHEN_INDICATOR_OOXML_Excel4Macros_EXEC : FILE
{
	meta:
		description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet"
		author = "ditekSHen"
		id = "674ef310-d3bc-5e15-862f-29aa111becb3"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L860-L873"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "ab3994e4082390f65d030db0b898a20df1d7e4b0ca2fdedc7a9d0f1480fd0334"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"

	strings:
		$ms = "<xm:macrosheet" ascii nocase
		$s1 = ">FORMULA.FILL(" ascii nocase
		$s2 = ">REGISTER(" ascii nocase
		$s3 = ">EXEC(" ascii nocase
		$s4 = ">RUN(" ascii nocase

	condition:
		uint32(0)==0x6d783f3c and $ms and (2 of ($s*) or ($s3))
}