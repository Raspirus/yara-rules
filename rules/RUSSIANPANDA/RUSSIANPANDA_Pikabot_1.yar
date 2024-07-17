rule RUSSIANPANDA_Pikabot_1 : FILE
{
	meta:
		description = "Detects PikaBot"
		author = "RussianPanda"
		id = "e740b821-69cc-5053-9f90-439b4364656f"
		date = "2024-01-02"
		modified = "2024-01-02"
		reference = "https://research.openanalysis.net/pikabot/debugging/string%20decryption/2023/11/12/new-pikabot.html"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/PikaBot/Pikabot_1-2-2024.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "f2dd26c23aba72c2b6b959fb411381b7d3a7466f94bf5259f57e96e44d3ee153"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {8A 04 11 30 02 42 83 EE 01 75 F5 5E C3}
		$s2 = {C0 E9 02 C0 E0 04 [13] C0 E2 06 02 D0}
		$s3 = {8D 53 BF 80 FA 19 0F B6 C3}

	condition:
		uint16(0)==0x5A4D and 2 of ($s*) and filesize <500KB
}