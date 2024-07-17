
rule ELASTIC_Windows_Hacktool_Sleepobfloader_460A1A75 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sleepobfloader (Windows.Hacktool.SleepObfLoader)"
		author = "Elastic Security"
		id = "460a1a75-7242-41d6-8b39-51f2f0276a33"
		date = "2024-01-24"
		modified = "2024-01-29"
		reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SleepObfLoader.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "84b3bc58ec04ab272544d31f5e573c0dd7812b56df4fa445194e7466f280e16d"
		logic_hash = "c0bc1b7ef71c1a91fc487f904315c6f187530ab39825f90f55ac36625d5b93cf"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8dbba5af9f379ac16a79b4989067b8715e084490ae2f048eb3a28d8d33c716e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { BA 01 00 00 00 41 B8 20 01 00 00 8B 48 3C 8B 4C 01 28 48 03 C8 48 89 0D ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B9 01 00 00 00 }
		$b = { 8A 50 20 83 60 24 F0 80 E2 F8 48 8B ?? ?? ?? 4C 8B ?? ?? ?? 48 89 08 48 8B ?? ?? ?? 48 89 48 08 }
		$c = { 8B 46 FB 41 89 40 18 0F B7 46 FF 66 41 89 40 1C 8A 46 01 41 88 40 1E }

	condition:
		all of them
}