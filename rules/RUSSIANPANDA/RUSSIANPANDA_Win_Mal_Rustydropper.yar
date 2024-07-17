
rule RUSSIANPANDA_Win_Mal_Rustydropper : FILE
{
	meta:
		description = "Detects RustyDropper"
		author = "RussianPanda"
		id = "9f217080-81e0-547a-9336-cf8ac2fadf36"
		date = "2024-03-01"
		modified = "2024-03-01"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/RustyDropper/win_mal_RustyDropper.yar#L1-L12"
		license_url = "N/A"
		hash = "a3a5e7011335a2284e2d4f73fd464ff129f0c9276878a054c1932bc50608584b"
		logic_hash = "d0c76bcd1af63cc1b1fbabc3fa33e6caafd7d9c7c3780a94a1ed37eadef655d7"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$s1 = {47 3a 5c 52 55 53 54 5f 44 52 4f 50 50 45 52 5f 45 58 45 5f 50 41 59 4c 4f 41 44 5c 44 52 4f 50 50 45 52 5f 4d 41 49 4e 5c}
		$s2 = {46 45 41 54 55 52 45 5f 42 52 4f 57 53 45 52 5f 45 4d 55 4c 41 54 49 4f 4e}

	condition:
		uint16(0)==0x5A4D and all of them
}