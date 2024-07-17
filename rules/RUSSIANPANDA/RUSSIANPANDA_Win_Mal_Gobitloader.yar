
rule RUSSIANPANDA_Win_Mal_Gobitloader : FILE
{
	meta:
		description = "Detects GoBitLoader"
		author = "RussianPanda"
		id = "4ebc7987-c1b2-5682-943f-7c19a9cb6b36"
		date = "2024-03-24"
		modified = "2024-03-24"
		reference = "https://www.malwarebytes.com/blog/threat-intelligence/2024/03/new-go-loader-pushes-rhadamanthys"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/GoBitLoader/win_mal_GoBitLoader.yar#L1-L13"
		license_url = "N/A"
		logic_hash = "66951b290bef6a6c9eef4ea674472465dfe0ec5072dce21f48b58191f7ce90e3"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$s1 = {6D 61 69 6E 2E 52 65 64 69 72 65 63 74 54 6F 50 61 79 6C 6F 61 64}
		$s2 = {6D 61 69 6E 2E 48 6F 6C 6C 6F 77 50 72 6F 63 65 73 73}
		$s3 = {6D 61 69 6E 2E 41 65 73 44 65 63 6F 64 65 2E 66 75 6E 63 31}

	condition:
		uint16(0)==0x5A4D and all of them
}