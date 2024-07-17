rule ELASTIC_Linux_Trojan_Mirai_3A85A418 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "3a85a418-2bd9-445a-86cb-657ca7edf566"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L458-L476"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "86a43b39b157f47ab12e9dc1013b4eec0e1792092d4cef2772a21a9bf4fc518a"
		logic_hash = "bd7fe497fb2557c9e9c26ec90e783f03cbbc9bdaa8d20b364ce65edf6c1e5fa3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "554aff5770bfe8fdeae94f5f5a0fd7f7786340a95633433d8e686af1c25b8cec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 01 D8 66 C1 C8 08 C1 C8 10 66 C1 C8 08 66 83 7C 24 2C FF 89 }

	condition:
		all of them
}