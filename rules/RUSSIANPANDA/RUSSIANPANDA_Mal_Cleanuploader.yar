rule RUSSIANPANDA_Mal_Cleanuploader : FILE
{
	meta:
		description = "Detects CleanUpLoader"
		author = "RussianPanda"
		id = "fc75fed2-0f8c-55c9-bd10-efe95a678f31"
		date = "2024-02-14"
		modified = "2024-02-14"
		reference = "https://x.com/AnFam17/status/1757871703282077857?s=20"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/CleanUpLoader/mal_cleanuploader.yar#L1-L14"
		license_url = "N/A"
		hash = "2b62dd154b431d8309002d5b4a35de07"
		logic_hash = "a9267c568c11420e36f0781469aa7d932c87d52707981912558eb0f4f84f673a"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {0F B6 80 30 82 42 00 88}
		$s2 = {44 69 73 6B 43 6C 72}
		$s3 = {49 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 20 00 45 00 64 00 67 00 65}

	condition:
		uint16(0)==0x5A4D and all of them and #s1>15
}