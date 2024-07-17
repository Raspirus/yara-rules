rule ELASTIC_Windows_Wiper_Hermeticwiper_7206A969 : FILE MEMORY
{
	meta:
		description = "Detects Windows Wiper Hermeticwiper (Windows.Wiper.HermeticWiper)"
		author = "Elastic Security"
		id = "7206a969-bbd6-4c2d-a19d-380b71a4ab08"
		date = "2022-02-24"
		modified = "2022-02-24"
		reference = "https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Wiper_HermeticWiper.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
		logic_hash = "84c61b8223a6ebf1ccfa4fdccee3c9091abca4553e55ac6c2492cff5503b4774"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e3486c785f99f4376d4161704afcaf61e8a5ab6101463a76d134469f8a5581bf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
		$a2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
		$a3 = "tdrv.pdb" ascii fullword
		$a4 = "%s%.2s" wide fullword
		$a5 = "ccessdri" ascii fullword
		$a6 = "Hermetica Digital"

	condition:
		all of them
}