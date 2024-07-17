rule RUSSIANPANDA_Win_Mal_Zloader : FILE
{
	meta:
		description = "Detects Zloader and other Zloader modules that employ the same encryption"
		author = "RussianPanda"
		id = "3f72e067-c82b-5c65-92c8-010955971d87"
		date = "2024-03-10"
		modified = "2024-03-10"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Zloader/win_mal_Zloader.yar#L1-L13"
		license_url = "N/A"
		logic_hash = "9ac9e8ca4a6f84e1bccac2292705ee6ebbc1595eb3f40ed777f7973e9bda7fc1"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {8B 45 ?? 89 45 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C1 8B 45 ?? 99 F7 F9 8B 45 ?? 48 63 D2 48 8D 0D ?? ?? ?? 00 0F BE 0C 11 31 C8 88 C2 48 8B 45 F0 48 63 4D}
		$s2 = {48 63 C9 44 0F B6 04 08 48 8B 45 E8 8B 4D D4 0F B6 14 08 44 31 C2 88 14 08 8B 45 D4}
		$s3 = {B9 11 00 00 00 99 F7 F9 8B [0-20] 31 C8 88 C2}
		$s4 = {8B 45 ?? BE 11 00 00 00 99 F7 [0-20] 83 F6 FF}

	condition:
		uint16(0)==0x5A4D and any of them
}