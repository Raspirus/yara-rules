
rule RUSSIANPANDA_Whitesnakestealer : FILE
{
	meta:
		description = "Detects WhiteSnake Stealer XOR samples "
		author = "RussianPanda"
		id = "cfe168a6-cc2f-5cfe-985c-78b232dc2651"
		date = "2023-07-04"
		modified = "2023-12-11"
		reference = "https://russianpanda.com/2023/07/04/WhiteSnake-Stealer-Malware-Analysis/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/WhiteSnake-Stealer/WhiteSnake_xor.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "0bd0e250b8598be297296ecf6644d3bf649e3dc4598438325a0913afed04c819"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {FE 0C 00 00 FE 09 00 00 FE 0C 02 00 6F ?? 00 00 0A FE 0C 03 00 61 D1 FE 0E 04 00 FE}
		$s2 = {61 6e 61 6c 2e 6a 70 67}

	condition:
		all of ($s*) and filesize <600KB
}