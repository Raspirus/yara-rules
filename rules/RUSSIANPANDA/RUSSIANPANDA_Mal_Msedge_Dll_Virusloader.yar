rule RUSSIANPANDA_Mal_Msedge_Dll_Virusloader : FILE
{
	meta:
		description = "Detects malicious msedge.dll file"
		author = "RussianPanda"
		id = "7139ee30-de9a-5ef0-a96f-2ab9c239c6ff"
		date = "2024-01-19"
		modified = "2024-01-19"
		reference = "https://blog.phylum.io/npm-package-found-delivering-sophisticated-rat/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/virusloader/mal_msedge_dll_virusloader.yar#L1-L16"
		license_url = "N/A"
		hash = "ab2e3b07170ef1516af3af0d03388868"
		logic_hash = "659fd5fa3121fec5bf4cceb6f3dea95bf4cbcde7441d6f11c35288d8ad75a803"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {C6 85 ?? FE FF FF ?? C6}
		$s2 = {C7 85 ?? FD FF FF}
		$s3 = {BF 60 01 00 00 [18] 30 04 39 41}

	condition:
		uint16(0)==0x5A4D and all of ($s*) and #s1>30 and #s2>30 and filesize <300KB
}