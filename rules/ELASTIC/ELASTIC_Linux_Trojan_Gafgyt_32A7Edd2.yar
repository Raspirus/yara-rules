
rule ELASTIC_Linux_Trojan_Gafgyt_32A7Edd2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "32a7edd2-175f-45b3-bf3d-8c842e4ae7e7"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1387-L1405"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
		logic_hash = "af26549c1cad0975735e2c233bc71e5e1b0e283d02552fdaea02656332ecd854"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d59183e8833272440a12b96de82866171f7ea0212cee0e2629c169fdde4da2a5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 75 FD 48 FD 45 FD 0F FD 00 FD FD 0F FD FD 02 00 00 48 FD 45 }

	condition:
		all of them
}