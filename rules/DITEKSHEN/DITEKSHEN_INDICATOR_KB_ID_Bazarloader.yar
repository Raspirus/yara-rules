
rule DITEKSHEN_INDICATOR_KB_ID_Bazarloader : FILE
{
	meta:
		description = "Detects Bazar executables with specific email addresses found in the code signing certificate"
		author = "ditekShen"
		id = "94b814e3-56c2-5cdb-9335-c92eea8ec668"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L11-L21"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "fd47a1d996c78a6efc144f0fe0a28951c34becab3101e7d25acc980bb6b9f8ce"
		score = 75
		quality = 71
		tags = "FILE"

	strings:
		$s1 = "skarabeyllc@gmail.com" ascii wide nocase
		$s2 = "admin@intell-it.ru" ascii wide nocase
		$s3 = "support@pro-kon.ru" ascii wide

	condition:
		uint16(0)==0x5a4d and any of them
}