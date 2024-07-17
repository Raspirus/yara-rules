rule RUSSIANPANDA_Purecrypter_Core : FILE
{
	meta:
		description = "Detects PureCrypter Core payload"
		author = "RussianPanda"
		id = "41aaa187-0fb5-53fe-a162-8d1a4974ccc1"
		date = "2024-01-09"
		modified = "2024-01-09"
		reference = "https://www.zscaler.com/blogs/security-research/technical-analysis-purecrypter"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/PureCrypter/purecrypter_core.yar#L3-L28"
		license_url = "N/A"
		hash = "e4faa7d7a098414449abffb210fd874798207ee9d27643c8088676ff429b56b7"
		logic_hash = "8c761a98369436ffbe1379152461753778985a42ae656567018b47c71af7d866"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$s1 = {47 5A 69 70 53 74 72 65 61 6D}
		$s2 = {41 73 73 65 6D 62 6C 79 4C 6F 61 64 65 72 00 43 6F 73 74 75 72 61}
		$s3 = {44 65 66 6C 61 74 65 53 74 72 65 61 6D}
		$cnct = {72 ?? ?? 00 70 28 FB 00 00 0A 72 ?? ?? 00 70 28 ?? 00 00 0A}
		$nr1 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
		$nr2 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}
		$nr3 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}
		$nr4 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}

	condition:
		filesize <5MB and all of ($s*) and dotnet.number_of_resources>4 and dotnet.number_of_resources<6 and 2 of ($nr*) and dotnet.assembly_refs[1].name contains "protobuf-net" and #cnct>5
}