
rule DITEKSHEN_INDICATOR_KB_ID_Amadey : FILE
{
	meta:
		description = "Detects Amadey executables with specific email addresses found in the code signing certificate"
		author = "ditekShen"
		id = "f9abbf1d-2077-52a8-bfb0-df3732649624"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L39-L47"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "3df3fe67835f76e51743b1b4fa2cbc48277d82689c2fc27457b4d7d820e56e43"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$s1 = "tochka.director@gmail.com" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and any of them
}