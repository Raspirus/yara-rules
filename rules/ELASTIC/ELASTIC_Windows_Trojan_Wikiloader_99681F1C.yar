
rule ELASTIC_Windows_Trojan_Wikiloader_99681F1C : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Wikiloader (Windows.Trojan.WikiLoader)"
		author = "Elastic Security"
		id = "99681f1c-8b32-4cb0-ab6b-640b316e587a"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_WikiLoader.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0b02cfe16ac73f2e7dc52eaf3b93279b7d02b3d64d061782dfed0c55ab621a8e"
		logic_hash = "fb293d74186e778856780377120ac2ebe9550a508a0b33e706c39f93a5509df8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1cd978adc6cbd36a5738fb4c26a2ba4aaa8e69a035bd2618ef2175b3bb2dc4b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 83 EC 08 48 89 E0 4C 89 20 48 83 EC 08 48 89 E0 4C 89 28 48 83 EC 08 48 89 E0 4C 89 30 48 83 EC 08 48 89 E0 4C 89 38 48 89 E5 48 83 EC 08 48 83 EC 60 48 89 CB 48 31 C0 48 89 E9 48 29 E1 48 }

	condition:
		all of them
}