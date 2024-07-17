rule RUSSIANPANDA_Zharkbot : FILE
{
	meta:
		description = "Detects ZharkBot"
		author = "RussianPanda"
		id = "54213d76-7e27-559d-b653-5390a0c6813c"
		date = "2024-01-21"
		modified = "2024-03-12"
		reference = "https://x.com/ViriBack/status/1749184882822029564?s=20"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/ZharkBot/zharkbot.yar#L1-L15"
		license_url = "N/A"
		hash = "d53ce8c0a8a89c2e3eb080849da8b1c47eaac614248fc55d03706dd5b4e10bdd"
		logic_hash = "ffaec6b19dd4385cd1bc156fdfde39a356367c7fba4135c48a8de62a18a78576"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {F7 EA C1 FA 04 8B C2 C1 E8 1F 03 C2 8B 55 ?? 0F BE C0 8A CA 6B C0 ?? 2A C8 80 C1}
		$s2 = {F7 E2 C1 EA 04 0F BE C2 8B 55 ?? 8A CA 6B C0 ?? 2A C8 80 C1 ?? 30 8C 15}

	condition:
		uint16(0)==0x5A4D and #s1>3 and #s2>3 and filesize <500KB
}