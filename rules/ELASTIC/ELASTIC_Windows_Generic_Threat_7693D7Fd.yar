
rule ELASTIC_Windows_Generic_Threat_7693D7Fd : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "7693d7fd-4161-4afb-8a8d-d487f2a7de5e"
		date = "2024-02-13"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2497-L2515"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc40cc5d0bd3722126302f74ace414e6934eca3a8a5c63a11feada2130b34b89"
		logic_hash = "886ad084f33faf8baae8a650a88095757c2cff9e18c8f5c50ff36120b43ec082"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "92489c8eb4f8a9da5e7bd858a47e20b342d70df1ba3a4769df06c434dc83d138"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 51 8B 45 08 83 65 FC 00 8B 00 0F B7 48 14 66 83 78 06 00 8D 4C 01 18 0F 86 9A 00 00 00 53 56 57 8D 59 24 8B 13 8B CA 8B F2 C1 E9 1D C1 EE 1E 8B FA 83 E1 01 83 E6 01 C1 EF 1F F7 C2 }

	condition:
		all of them
}