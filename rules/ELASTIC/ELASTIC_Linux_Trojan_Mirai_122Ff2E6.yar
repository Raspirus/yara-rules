rule ELASTIC_Linux_Trojan_Mirai_122Ff2E6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "122ff2e6-56e6-4aa8-a3ec-c19d31eb1f80"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L219-L237"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c7dd999a033fa3edc1936785b87cd69ce2f5cac5a084ddfaf527a1094e718bc4"
		logic_hash = "62884309b9095cdd6219c9ef6cd77a0f712640d8a1db4afe5b1d01f4bbe5acc2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3c9ffd7537e30a21eefa6c174f801264b92a85a1bc73e34e6dc9e29f84658348"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 EB 15 89 F0 83 C8 01 EB 03 8B 5B 08 3B 43 04 72 F8 8B 4B 0C 89 }

	condition:
		all of them
}