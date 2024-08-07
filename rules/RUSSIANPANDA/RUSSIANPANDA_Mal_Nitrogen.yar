
rule RUSSIANPANDA_Mal_Nitrogen : FILE
{
	meta:
		description = "Detects Nitrogen campaign"
		author = "RussianPanda"
		id = "9d591f87-47ec-54ea-b0ae-26a0542733a0"
		date = "2024-02-04"
		modified = "2024-02-04"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Nitrogen/mal_nitrogen.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "642d5a16c7fb217a297bba683221de474eb028ac48ec8f52be897eaa056acb9b"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$s1 = {63 7C 77 7B F2 6B 6F C5}
		$s2 = {52 09 6A D5 30 36 A5 38}
		$s3 = {6F 72 69 67 69 6E 61 6C 5F 69 6E 73 74 61 6C 6C}
		$s4 = {43 3A 5C 55 73 65 72 73 5C 50 75 62 6C 69 63 5C 44 6F 77 6E 6C 6F 61 64}
		$s5 = {25 00 43 00 55 00 52 00 52 00 45 00 4E 00 54 00 5F 00 44 00 45 00 52 00 45 00 43 00 54 00 4F 00 52 00 59 00 25}
		$s6 = {4E 69 74 72 6F 67 65 6E 54 61 72 67 65 74}

	condition:
		uint16(0)==0x5A4D and 5 of them
}