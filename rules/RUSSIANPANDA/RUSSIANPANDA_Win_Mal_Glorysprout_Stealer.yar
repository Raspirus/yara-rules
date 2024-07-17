
rule RUSSIANPANDA_Win_Mal_Glorysprout_Stealer : FILE
{
	meta:
		description = "Detects GlorySprout Stealer"
		author = "RussianPanda"
		id = "44c50f20-479e-5960-9ab9-97b9a17d7cbf"
		date = "2024-03-16"
		modified = "2024-03-16"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/GlorySprout/win_mal_GlorySprout_Stealer.yar#L1-L13"
		license_url = "N/A"
		hash = "8996c252fc41b7ec0ec73ce814e84136be6efef898822146c25af2330f4fd04a"
		logic_hash = "c843f7924e69c1b9fc3676178aa630319fe25605deddcd73c4905c51cc97d7eb"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {25 0F 00 00 80 79 05 48 83 C8 F0 40}
		$s2 = {8B 82 A4 00 00 00 8B F9 89 06 8D 4E 0C 8B 82 A8 00 00 00 89 46 04 0F B7 92 AC 00 00 00 89 56 08}
		$s3 = {0F B6 06 C1 E7 04 03 F8 8B C7 25 00 00 00 F0 74 0B C1 E8 18}

	condition:
		uint16(0)==0x5A4D and all of them and #s1>100
}