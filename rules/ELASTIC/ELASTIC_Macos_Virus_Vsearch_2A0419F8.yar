
rule ELASTIC_Macos_Virus_Vsearch_2A0419F8 : FILE MEMORY
{
	meta:
		description = "Detects Macos Virus Vsearch (MacOS.Virus.Vsearch)"
		author = "Elastic Security"
		id = "2a0419f8-95b2-4f87-a37a-ee0b65e344e9"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Virus_Vsearch.yar#L20-L37"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "fa9b811465e435bff5bc0f149ff65f57932c94f548a5ece4ec54ba775cdbb55a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2da9f0fc05bc8e23feb33b27142f46fb437af77766e39889a02ea843d52d17eb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 6F 72 6D 61 6C 2F 69 33 38 36 2F 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6F 00 }

	condition:
		all of them
}