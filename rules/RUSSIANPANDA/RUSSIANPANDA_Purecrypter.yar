rule RUSSIANPANDA_Purecrypter : FILE
{
	meta:
		description = "Detects PureCrypter"
		author = "RussianPanda"
		id = "5670772c-ada1-55fa-b7fd-9dadd1756259"
		date = "2024-01-09"
		modified = "2024-01-09"
		reference = "https://www.zscaler.com/blogs/security-research/technical-analysis-purecrypter"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/PureCrypter/purecrypter.yar#L3-L22"
		license_url = "N/A"
		hash = "566d8749e166436792dfcbb5e5514f18c9afc0e1314833ac2e3d86f37ff2030f"
		logic_hash = "dd8592fa0b7d240d23235008601500a20e068032f6dcd6e90a38b06ac747b8af"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {28 ?? 00 00 ?? 28 02 00 00 2B 28 ?? 00 00 (0A|06)}
		$s2 = {73 ?? 00 00 0A}
		$s3 = {73 ?? 00 00 06 6F ?? 00 00 06}
		$s4 = {52 65 73 6F 75 72 63 65 4D 61 6E 61 67 65 72}
		$s5 = {28 ?? 00 00 ?? 6F ?? 00 00 0A 28 03 00 00 2B ?? 6F ?? 00 00 0A 28 ?? 00 00 2B}

	condition:
		filesize <6MB and 4 of ($s*) and dotnet.number_of_resources>0 and dotnet.number_of_resources<2 and dotnet.resources[0].length>300KB
}