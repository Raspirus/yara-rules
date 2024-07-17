rule RUSSIANPANDA_Purelogs_Stealer_Core : FILE
{
	meta:
		description = "Detects Pure Logs Stealer Core Payload"
		author = "RussianPanda"
		id = "bda876c3-76ce-5e1e-8dd4-f06e8240fc11"
		date = "2023-12-26"
		modified = "2024-01-10"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Pure Logs Stealer/purelogs_stealer_core.yar#L3-L18"
		license_url = "N/A"
		logic_hash = "7388299ebcc70aeb86c46c29a787f790993a67148d9f3968def1109e45f69452"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {7E 58 00 00 0A [15] 28 20 00 00 0A 18 6F 0A 02 00 0A 0B}
		$s2 = {50 6C 67 43 6F 72 65}
		$s3 = {7E 64 01 00 0A 28 65 01 00 0A}

	condition:
		all of ($s*) and filesize <5MB and pe.imports("mscoree.dll")
}