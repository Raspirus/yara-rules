
rule ELASTIC_Linux_Trojan_Mirai_Fe721Dc5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "fe721dc5-c2bc-4fa6-bdbc-589c6e033e6b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1067-L1084"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e9312eefb5f14a27d96e973139e45098c2f62a24d5254ca24dea64b9888a4448"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ab7f571a3a3f6b50b9e120612b3cc34d654fc824429a2971054ca0d078ecb983"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 18 EB E1 57 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 }

	condition:
		all of them
}