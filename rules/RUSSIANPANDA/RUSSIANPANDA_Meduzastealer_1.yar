
rule RUSSIANPANDA_Meduzastealer_1 : FILE
{
	meta:
		description = "Detects MeduzaStealer 1-2024"
		author = "RussianPanda"
		id = "6bc4c048-a32d-5a9c-b213-980c64d08d29"
		date = "2024-01-01"
		modified = "2024-01-01"
		reference = "https://russianpanda.com/2023/06/28/Meduza-Stealer-or-The-Return-of-The-Infamous-Aurora-Stealer/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/MeduzaStealer/MeduzaStealer_1-1-2024.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "0547e51abd04302c45f1319bc21046ade019bc98eb85d9cba67cb2109ff642eb"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 57 69 6e 55 70 64 61 74 65 2e 65 78 65}
		$s2 = {0f 57 ?? ?? ?? 00 00 66 0f 7f 85 ?? ?? 00 00}
		$s3 = {48 8d 15 ?? ?? 05 00 49 8b cf}
		$s4 = {48 8d 0d ?? ?? 06 00 ff 15 ?? ?? 06 00}

	condition:
		3 of ($s*) and filesize <1MB
}