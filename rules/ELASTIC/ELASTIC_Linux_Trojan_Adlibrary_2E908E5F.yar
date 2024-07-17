
rule ELASTIC_Linux_Trojan_Adlibrary_2E908E5F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Adlibrary (Linux.Trojan.Adlibrary)"
		author = "Elastic Security"
		id = "2e908e5f-f79e-491f-8959-86b7cffd35c0"
		date = "2022-08-23"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Adlibrary.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "acb22b88ecfb31664dc07b2cb3490b78d949cd35a67f3fdcd65b1a4335f728f1"
		logic_hash = "0d0df636876adf0268b7a409bfc9d8bfad298793d11297596ef91aeba86889da"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "27ea79ad607f0dbd3d7892e27be9c142b0ac3a2b56f952f58663ff1fe68d6c88"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 32 04 39 83 C7 01 0F BE C0 89 04 24 E8 ?? ?? ?? ?? 3B 7C 24 ?? B8 00 00 00 00 0F 44 F8 83 C5 01 81 FD }

	condition:
		all of them
}