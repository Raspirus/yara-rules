rule ELASTIC_Linux_Trojan_Mirai_Eedfbfc6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "eedfbfc6-98a4-4817-a0d6-dcb065307f5c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L537-L555"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b7342f7437a3a16805a7a8d4a667e0e018584f9a99591413650e05d21d3e6da6"
		logic_hash = "949b32db1a00570fc84fbbe510f57f6e898d089efd3fedbd7719f8059021b6bc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c79058b4a40630cb4142493062318cdfda881259ac95b70d977816f85b82bb36"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 7C 39 57 52 AC 57 A8 CE A8 8C FC 53 A8 A8 0E 33 C2 AA 38 14 FB 29 }

	condition:
		all of them
}