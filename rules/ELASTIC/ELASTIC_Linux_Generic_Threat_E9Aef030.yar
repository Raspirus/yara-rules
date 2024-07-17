rule ELASTIC_Linux_Generic_Threat_E9Aef030 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "e9aef030-7d8c-4e9d-a364-178c717516f0"
		date = "2024-05-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L1152-L1170"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5ab72be12cca8275d95a90188a1584d67f95d43a7903987e734002983b5a3925"
		logic_hash = "1d458e147d6667e2e0740d6d26fee05ac02f49e9eba30002852e723308b1b462"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "50ae1497132a9f1afc6af5bf96a0a49ca00023d5f0837cb8d67b4fd8b0864cc7"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { D0 4D E2 00 50 A0 E1 0A 00 00 0A 38 40 80 E2 28 31 9F E5 10 00 8D E2 24 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 40 00 13 E2 05 }

	condition:
		all of them
}