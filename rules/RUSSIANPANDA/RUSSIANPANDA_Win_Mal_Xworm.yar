
rule RUSSIANPANDA_Win_Mal_Xworm : FILE
{
	meta:
		description = "Detects XWorm RAT"
		author = "RussianPanda"
		id = "5701f382-3c97-5a00-9673-6c39b0f11cc2"
		date = "2024-03-11"
		modified = "2024-03-11"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/XWorm/win_mal_XWorm.yar#L1-L15"
		license_url = "N/A"
		hash = "fc422800144383ef6e2e0eee37e7d6ba"
		logic_hash = "c42544285517dc61628e8df2ee5ab6733924fbb2cc08b9b2df273eec0a401d90"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21}
		$s2 = {50 00 6C 00 75 00 67 00 69 00 6E 00 73 00 20 00 52 00 65 00 6D 00 6F 00 76 00 65 00 64 00 21}
		$s3 = {73 00 65 00 6E 00 64 00 50 00 6C 00 75 00 67 00 69 00 6E}
		$s4 = {4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21}
		$s5 = "_CorExeMain"

	condition:
		uint16(0)==0x5A4D and all of them
}