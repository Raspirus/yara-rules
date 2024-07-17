rule ELASTIC_Linux_Trojan_Gafgyt_4F43B164 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "4f43b164-686d-4b73-b532-45e2df992b33"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L991-L1009"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f0fdb3de75f85e199766bbb39722865cac578cde754afa2d2f065ef028eec788"
		logic_hash = "79a17e70e9b7af6e53f62211c33355a4c46a82e7c4e80c20ffe9684e24155808"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "35a885850a06e7991c3a8612bbcdfc279b87e4ca549723192d3011a1e0a81640"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 46 00 4B 49 4C 4C 53 55 42 00 4B 49 4C 4C 53 55 42 20 3C 73 }

	condition:
		all of them
}