rule ELASTIC_Windows_Generic_Threat_20469956 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "20469956-1be6-48e8-b3c4-5706f9630971"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L222-L240"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a1f2923f68f5963499a64bfd0affe0a729f5e7bd6bcccfb9bed1d62831a93c47"
		logic_hash = "da351bec0039a32bb9de1d8623ab3dc26eb752d30a64e613de96f70e1b1c2463"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "67cec754102e3675b4e72ff4826c40614e4856b9cbf12489de3406318990fc85"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 E4 F8 83 EC 5C 53 56 33 C0 C7 44 24 18 6B 00 6C 00 57 8D 4C 24 1C C7 44 24 20 69 00 66 00 C7 44 24 24 2E 00 73 00 C7 44 24 28 79 00 73 00 66 89 44 24 2C C7 44 24 0C 6B 00 6C 00 C7 }

	condition:
		all of them
}