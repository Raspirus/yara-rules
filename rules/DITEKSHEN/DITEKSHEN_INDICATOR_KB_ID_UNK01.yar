
rule DITEKSHEN_INDICATOR_KB_ID_UNK01 : FILE
{
	meta:
		description = "Detects Amadey executables with specific email addresses found in the code signing certificate"
		author = "ditekShen"
		id = "56e83bfb-e17d-5d27-87fa-e275cc540148"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L49-L58"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "d85461f74186fcabcbf7f2bc1dce06b0012c504cf3235a6fc3e1499dc6f8a3ee"
		score = 75
		quality = 73
		tags = "FILE"
		hash1 = "37d08a64868c35c5bae8f5155cc669486590951ea80dd9da61ec38defb89a146"

	strings:
		$s1 = "etienne@tetracerous.br" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and any of them
}