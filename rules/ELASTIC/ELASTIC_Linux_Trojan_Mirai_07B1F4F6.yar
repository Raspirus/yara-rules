rule ELASTIC_Linux_Trojan_Mirai_07B1F4F6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "07b1f4f6-9324-48ab-9086-b738fdaf47c3"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1882-L1900"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
		logic_hash = "4af1a20e29e0c9b62e1530031e49a3d7b37d4e9a547d89a270a2e59e0c7852cc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bebafc3c8e68b36c04dc9af630b81f9d56939818d448759fdd83067e4c97e87a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FD 08 FD 5C 24 48 66 FD 07 66 FD 44 24 2E 66 FD FD 08 66 FD 47 }

	condition:
		all of them
}