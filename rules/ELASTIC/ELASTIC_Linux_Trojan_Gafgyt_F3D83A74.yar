rule ELASTIC_Linux_Trojan_Gafgyt_F3D83A74 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "f3d83a74-2888-435a-9a3c-b7de25084e9a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L218-L236"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		logic_hash = "2db46180e66c9268a97d63cd1c4eb8439e6882b4e3277bc4848e940e4d25482f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1c5df68501b688905484ed47dc588306828aa7c114644428e22e5021bb39bd4a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { DC 00 74 1B 83 7D E0 0A 75 15 83 7D E4 00 79 0F C7 45 C8 01 00 }

	condition:
		all of them
}