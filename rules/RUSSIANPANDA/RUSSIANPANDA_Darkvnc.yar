
rule RUSSIANPANDA_Darkvnc : FILE
{
	meta:
		description = "Detects DarkVNC"
		author = "RussianPanda"
		id = "dbc86ac8-5ea3-59a7-b3ab-68c603165720"
		date = "2024-01-15"
		modified = "2024-01-15"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/DarkVNC/darkvnc.yar#L1-L15"
		license_url = "N/A"
		hash = "3c74dccd06605bcf527ffc27b3122959"
		logic_hash = "1dd1246e0b22181706433f0cff9b231017e747d8faaa2db4cb9adefeab492ab7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {66 89 84 24 ?? 00 00 00 B8 ?? 00 00 00}
		$s2 = {66 31 14 41 48}
		$s3 = "VncStopServer"
		$s4 = "VncStartServer"

	condition:
		uint16(0)==0x5A4D and 3 of them and filesize <700KB
}