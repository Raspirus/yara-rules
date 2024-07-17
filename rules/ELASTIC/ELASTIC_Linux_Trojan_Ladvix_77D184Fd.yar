
rule ELASTIC_Linux_Trojan_Ladvix_77D184Fd : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ladvix (Linux.Trojan.Ladvix)"
		author = "Elastic Security"
		id = "77d184fd-a15e-40e5-ac7e-0d914cc009fe"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ladvix.yar#L20-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1bb44b567b3c82f7ee0e08b16f7326d1af57efe77d608a96b2df43aab5faa9f7"
		logic_hash = "0ae9c41d3eb7964344f71b9708278a0e83776228e4455cf0ad7c08e288305203"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "21361ca7c26c98903626d1167747c6fd11a5ae0d6298d2ef86430ce5be0ecd1a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 40 10 48 89 45 80 8B 85 64 FF FF FF 48 89 E2 48 89 D3 48 63 D0 48 83 }

	condition:
		all of them
}