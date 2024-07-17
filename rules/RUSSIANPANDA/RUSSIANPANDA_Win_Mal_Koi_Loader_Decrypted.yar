
rule RUSSIANPANDA_Win_Mal_Koi_Loader_Decrypted : FILE
{
	meta:
		description = "Detects decrypted Koi Loader"
		author = "RussianPanda"
		id = "71de93d3-5c9f-5994-a54d-d4455d500280"
		date = "2024-04-04"
		modified = "2024-04-04"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Koi/win_mal_Koi_loader_decrypted.yar#L1-L12"
		license_url = "N/A"
		hash = "1901593e0299930d46b963866f33a93b"
		logic_hash = "f73ada7185ff109afe1e186a0fb7b4420b3d0e04c93c7c5423243db97eb34e49"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {73 00 64 00 32 00 2E 00 70 00 73 00 31 00}
		$s2 = {25 00 74 00 65 00 6D 00 70 00 25 00 5C 00 25 00 70 00 61 00 74 00 68 00 73 00 25}

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}