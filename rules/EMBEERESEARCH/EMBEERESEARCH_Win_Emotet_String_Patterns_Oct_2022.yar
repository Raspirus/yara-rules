rule EMBEERESEARCH_Win_Emotet_String_Patterns_Oct_2022 : FILE
{
	meta:
		description = "Detection of string hashing routines observed in emotet"
		author = "Embee_Research @ HuntressLabs"
		id = "fd9c3133-95dc-5dd8-9e94-ed85ad8e1fc7"
		date = "2022-10-14"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/2022/win_emotet_string_patterns_oct_2022.yar#L1-L19"
		license_url = "N/A"
		logic_hash = "36f4a3fed124b8c25711f706c5b4f1c9b0801c2105cf86077b8c002dd70a6fbc"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$em1 = {45 33 f6 4c 8b d0 48 85 c0 74 64 48 8d 14 b3 4c 8b c0 45 8b de 4c 8b ca 4c 2b cb 49 83 c1 03 49 c1 e9 02 48 3b da 4d 0f 47 ce}
		$em2 = {8b cd 49 ff c3 33 0b 48 8d 5b 04 0f b6 c1 66 41 89 00 0f b7 c1 c1 e9 10 66 c1 e8 08 4d 8d 40 08 66 41 89 40 fa 0f b6 c1 66 c1 e9 08 66 41 89 40 fc 66 41 89 48 fe 4d 3b d9}
		$em3 = {49 ff c3 33 0b 48 8d 5b 04 0f b6 c1 66 41 89 00}
		$em4 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be c1 03 d0 41 2b d0 49 ff c2 44 8b c2}

	condition:
		uint16(0)==0x5a4d and ( any of them )
}