
rule ELASTIC_Linux_Trojan_Gafgyt_31796A40 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "31796a40-1cbe-4d0c-a785-d16f40765f4a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L356-L374"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "227c7f13f7bdadf6a14cc85e8d2106b9d69ab80abe6fc0056af5edef3621d4fb"
		logic_hash = "0e0e901d12edd77e77a205f8547f891f483fc8676493e9b7a324e970225af3c9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0a6c56eeed58a1a100c9b981157bb864904ffddb3a0c4cb61ec4cc0d770d68ae"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 14 48 63 D0 48 8D 45 C0 48 8D 70 04 48 8B 45 E8 48 8B 40 18 48 }

	condition:
		all of them
}