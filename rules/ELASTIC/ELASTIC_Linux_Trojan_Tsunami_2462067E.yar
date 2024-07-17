
rule ELASTIC_Linux_Trojan_Tsunami_2462067E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "2462067e-06cf-409c-8184-86bd7a772690"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L221-L239"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3847f1c7c15ce771613079419de3d5e8adc07208e1fefa23f7dd416b532853a1"
		logic_hash = "cf6c0703f9108f8193e0a9c18ba3d76263527a13fe44e194fa464d399512ae05"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f84d62ad2d6f907a47ea9ff565619648564b7003003dc8f20e28a582a8331e6b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 45 F4 8B 40 0C 89 C1 8B 45 F4 8B 40 10 8B 10 8D 45 E4 89 C7 }

	condition:
		all of them
}