
rule RUSSIANPANDA_Neptune_Loader : FILE
{
	meta:
		description = "Detects Neptune Loader"
		author = "RussianPanda"
		id = "d576bf47-10bd-55d0-99b0-69c02dc87f17"
		date = "2024-01-17"
		modified = "2024-01-21"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/NeptuneLoader/neptune_loader.yar#L1-L18"
		license_url = "N/A"
		logic_hash = "ca54b8a624d48aa28bc727420f25e6f0fd67b193ac79443a357d88a9fe7cbdbb"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$s1 = {8B C6 E8 F4 FB FF FF}
		$s2 = {66 33 D1 66 89 54 58 FE}
		$s3 = {7C 53 74 61 72 74 75 70 46 6F 6C 64 65 72 7C}
		$s4 = {44 65 6C 70 68 69}
		$t1 = {C7 [3] 0B 40 40 00 [6] A1 ?? 61 40 00}
		$t2 = {C7 ?? 24 00 40 40 00 A1 ?? 61 40 00}
		$t3 = {8B ?? ?? FF D0 B8}

	condition:
		uint16(0)==0x5A4D and 3 of ($s*) or 2 of ($t*) and filesize <6MB
}