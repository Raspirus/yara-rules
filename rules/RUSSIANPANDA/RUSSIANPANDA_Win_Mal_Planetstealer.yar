
rule RUSSIANPANDA_Win_Mal_Planetstealer : FILE
{
	meta:
		description = "Detects PlanetStealer"
		author = "RussianPanda"
		id = "f912066f-4151-5f83-8d34-6bffdf9e25e5"
		date = "2024-03-04"
		modified = "2024-03-24"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/PlanetStealer/win_mal_PlanetStealer.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "e1660d6fed4c48b45b40bd51fb52254c5b19ca6f1938b68f2344bde473820b86"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$s1 = {48 8D 15 ?? ?? ?? 00 0F B6 34 10 0F B6 BC 04 ?? ?? 00 00 ?? ?? 40 88 ?? 04 ?? ?? 00 00 48 FF C0}
		$s2 = {48 83 F8 ?? 7C DA}
		$s3 = {72 75 6E 74 69 6D 65 2E 67 6F 62 75 66}
		$s4 = {74 6F 74 61 6C 5F 77 61 6C 6C 65 74 73}
		$s5 = {74 6F 74 61 6C 5F 63 6F 6F 6B 69 65 73}

	condition:
		uint16(0)==0x5A4D and all of them and #s2>100 and #s1>100 and filesize <20MB
}