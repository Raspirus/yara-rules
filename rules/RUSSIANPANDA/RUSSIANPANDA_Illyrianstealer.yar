rule RUSSIANPANDA_Illyrianstealer : FILE
{
	meta:
		description = "Detects Illyrian Stealer"
		author = "RussianPanda"
		id = "2f85e87c-6883-5f41-a37c-00f9e93f61bf"
		date = "2024-01-08"
		modified = "2024-01-08"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/IllyrianStealer/illyrian_stealer.yar#L2-L18"
		license_url = "N/A"
		hash = "fae0aed6173804e8c22027cbb0c121eedd927f16ea7e2b23662dbe6e016980e8"
		logic_hash = "2012d401d3e7ce2d4d6ea12ed01a30b7d3e18f4ed47dbf70d43bae6c328960ea"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "get_TotalPhysicalMemory"
		$s2 = "\\b(bitcoincash)[a-zA-HJ-NP-Z0-9]{36,54}\\b" wide
		$s3 = "[Crypto]" wide
		$s4 = "|Black|" wide

	condition:
		all of ($s*) and filesize <50KB and pe.imports("mscoree.dll")
}