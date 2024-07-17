
rule RUSSIANPANDA_Easycrypter : FILE
{
	meta:
		description = "Detects EasyCrypter"
		author = "RussianPanda"
		id = "73b01a6c-dcd1-502e-a431-daf82ab3ed50"
		date = "2024-01-05"
		modified = "2024-01-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/EasyCrypter/easycrypter.yar#L1-L16"
		license_url = "N/A"
		hash = "60063c99fda3b6c5c839ec1c310b03e8f9c7c8823f2eb7bf75e22c6d738ffa8f"
		logic_hash = "761ed4629150453009b76d9c2ad251754009b464550b92dab3395fa30422f6ef"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {F6 17 [16-20] 80 2F 36 [16-20] 80 07 87}
		$s2 = {81 38 50 45 00 00 [20-22] 8B 88 A0 00 00 00 [2-4] 8B 80 A4 00 00 00 [5-7] 8B 40 50 [50-56] 89 0C 24 89 44 24 04 C7 44 24 08 00 30 00 00 C7 44 24 0C 04 00 00 00 FF 15 [3] 00}

	condition:
		uint16(0)==0x5A4D and $s1 and $s2
}