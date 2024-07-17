
rule DITEKSHEN_INDICATOR_XML_Webrelframe_Remotetemplate : FILE
{
	meta:
		description = "Detects XML web frame relations refrencing an external target in dropper OOXML documents"
		author = "ditekSHen"
		id = "724650db-8d58-5e73-92e7-287890babc3b"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L717-L727"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "fbe209e31ddb4369de02b6e91bf65f0588089c7b838dcf80f182248790b59e20"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$target1 = "/frame\" Target=\"http" ascii nocase
		$target2 = "/frame\" Target=\"file" ascii nocase
		$mode = "TargetMode=\"External" ascii

	condition:
		uint32(0)==0x6d783f3c and (1 of ($target*) and $mode)
}