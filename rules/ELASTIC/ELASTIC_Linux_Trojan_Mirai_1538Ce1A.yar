
rule ELASTIC_Linux_Trojan_Mirai_1538Ce1A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "1538ce1a-7078-4be3-bd69-7e692a1237f5"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1862-L1880"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
		logic_hash = "cf2dd11da520640c6a64e05c4679072a714d8cf93d5f5aa3a1eca8eb3e9c8b3b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f3d82cae74db83b7a49c5ec04d1a95c3b17ab1b935de24ca5c34e9b99db36803"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FD 00 00 00 FD 34 FD FD 04 40 FD 04 FD FD 7E 14 FD 78 14 1F 0F }

	condition:
		all of them
}