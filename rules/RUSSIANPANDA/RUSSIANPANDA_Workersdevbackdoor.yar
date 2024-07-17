rule RUSSIANPANDA_Workersdevbackdoor : FILE
{
	meta:
		description = "Detects WorkersDevBackdoor"
		author = "RussianPanda"
		id = "725e0924-c108-5927-8d27-e4bc5b284883"
		date = "2023-12-15"
		modified = "2024-01-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/WorkersDevBackdoor/WorkDevBackdoor.yar#L3-L20"
		license_url = "N/A"
		logic_hash = "f92ad9dc657d87a47e539ea2ee896f9b86bb95e51a890a838c6e6b0efa5deb7d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 20 00 7B 00 30 00 7D 00 20 00 7B 00 31 00 7D}
		$s2 = {72 FB 00 00 70 72 13 01 00 70 28 20 00 00 0A 72 2D 01 00 70}
		$s3 = {55 00 53 00 45 00 52 00 44 00 4F 00 4D 00 41 00 49 00 4E}
		$s4 = {43 00 4F 00 4D 00 50 00 55 00 54 00 45 00 52 00 4E 00 41 00 4D 00 45}

	condition:
		3 of ($s*) and pe.imports("mscoree.dll") and filesize <2MB
}