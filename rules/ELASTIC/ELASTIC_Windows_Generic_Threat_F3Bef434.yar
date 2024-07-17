rule ELASTIC_Windows_Generic_Threat_F3Bef434 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "f3bef434-0688-4672-a02f-40615cc429b1"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1035-L1053"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "98d538c8f074d831b7a91e549e78f6549db5d2c53a10dbe82209d15d1c2e9b56"
		logic_hash = "efba0e1fbe6562a9aeaac23b851c31350e4ac6551e505be4986bddade92ca303"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a05dfdf2f8f15335acb2772074ad42f306a4b33ab6a19bdac99a0215820a6f7b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 6F 70 00 06 EB 72 06 26 0A 00 01 45 6F 04 00 00 8F 7B 02 06 26 0A 00 01 44 6F 70 00 06 D5 72 00 00 00 B8 38 1D 2C EB 2C 1A 00 00 00 B8 38 14 04 00 00 8F 7B 00 00 00 BD 38 32 2C 00 00 00 BE 38 }

	condition:
		all of them
}