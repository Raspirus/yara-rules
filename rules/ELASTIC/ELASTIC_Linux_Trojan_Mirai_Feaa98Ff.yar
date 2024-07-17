rule ELASTIC_Linux_Trojan_Mirai_Feaa98Ff : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "feaa98ff-6cd9-40bb-8c4f-ea7c79b272f3"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1902-L1920"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
		logic_hash = "06be9d8bcfcb7e6b600103cf29fa8a94a457ff56e8c7018336c270978a57ccbf"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0bc8ba390a11e205624bc8035b1d1e22337a5179a81d354178fa2546c61cdeb0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F FD FD FD FD FD FD 7A 03 41 74 5E 42 31 FD FD 6E FD FD FD FD }

	condition:
		all of them
}