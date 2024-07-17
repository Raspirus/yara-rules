rule ELASTIC_Linux_Trojan_Snessik_D166F98C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Snessik (Linux.Trojan.Snessik)"
		author = "Elastic Security"
		id = "d166f98c-0fa3-4a1b-a6d2-7fbe4e338fc7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Snessik.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3ececc2edfff2f92d80ed3a5140af55b6bebf7cae8642a0d46843162eeddddd"
		logic_hash = "44f15a87d48338aafa408d4bcabef844c8864cd95640ad99208b5035e28ccd27"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6247d59326ea71426862e1b242c7354ee369fbe6ea766e40736e2f5a6410c8d7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D2 74 3B 83 CA FF F0 0F C1 57 10 85 D2 7F 9F 48 8D 74 24 2E 89 44 }

	condition:
		all of them
}