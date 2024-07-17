rule ELASTIC_Linux_Trojan_Mirai_E43A8744 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "e43a8744-1c52-4f95-bd16-be6722bc4d1a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1264-L1282"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
		logic_hash = "17c52d2b720fa2e98c3e9bb077525a695a6e547a66e8c44fcc1e26e48df81adf"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e7ead3d1a51f0d7435a6964293a45cb8fadd739afb23dc48c1d81fbc593b23ef"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 23 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }

	condition:
		all of them
}