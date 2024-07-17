rule RUSSIANPANDA_Solarphantom : FILE
{
	meta:
		description = "SolarPhantom Backdoor Detection"
		author = "RussianPanda"
		id = "f564a943-e83b-5c1b-ba8c-b227d69d3fd8"
		date = "2023-12-11"
		modified = "2023-12-11"
		reference = "https://www.esentire.com/blog/solarmarker-to-jupyter-and-back"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/SolarMarker/solarphantom.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "3b49d301e625d5abf1b726481a80d6a97d33acd3301c12964f2f37d37130c1b7"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$p1 = {B8 94 E3 46 00 E8 C6 EB FA FF 8B 45 F8}
		$p2 = {68 E8 EF 46 00 FF 75 E4}
		$p3 = {62 72 76 70 72 66 5f 62 6b 70}

	condition:
		uint16(0)==0x5A4D and 1 of ($p*) and filesize <600KB
}