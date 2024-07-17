
rule RUSSIANPANDA_PSWSTEALER : FILE
{
	meta:
		description = "PSWSTEALER"
		author = "RussianPanda"
		id = "8a596074-ffe3-5979-b384-487ebe8b953c"
		date = "2023-04-02"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/PSWSTEALER/pswstealer.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "7d85b0ccaa07419f22b9f38a4bc66435cd689b21fa7e4584ef8bea485b6bd2c1"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$obf = {09 20 FF [3] 5F 06 25 17 58 0A 61 1E 62 09 1E 63 06 25 17 58 0A 61 D2 60 D1 9D}
		$obf1 = {09 06 08 59 61 D2 13 04 09 1E 63 08 61 D2 13 05 07 08 11 05 1E 62 11 04 60 D1 9D 08 17 58 0C}
		$enc = {73 ?? 00 00 0A 73 ?? 00 00 0A}
		$s = {73 ?? 00 00 0A 0C 08 6F ?? 00 00 0A}

	condition:
		all of them and filesize <200KB
}