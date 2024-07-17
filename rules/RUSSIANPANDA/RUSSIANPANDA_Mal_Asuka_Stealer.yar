
rule RUSSIANPANDA_Mal_Asuka_Stealer : FILE
{
	meta:
		description = "Detects AsukaStealer"
		author = "RussianPanda"
		id = "a718be5f-dc76-5610-9237-038a9719d7e5"
		date = "2024-02-02"
		modified = "2024-03-18"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/AsukaStealer/mal_asuka_stealer.yar#L1-L12"
		license_url = "N/A"
		logic_hash = "7974e0de821ddcafd4f00b27d587108f0d80f8a231dd0db4d2be4fa6ab44fef4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {32 14 3E E8 F6 81 00 00}
		$s2 = {00 58 00 2D 00 43 00 6F 00 6E 00 66 00 69 00 67}
		$s3 = {58 00 2D 00 49 00 6E 00 66 00 6F}

	condition:
		uint16(0)==0x5A4D and all of them
}