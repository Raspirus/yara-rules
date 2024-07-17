rule ELASTIC_Linux_Trojan_Gafgyt_32Eb0C81 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "32eb0c81-25af-4670-ab77-07ea7ce1874a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1089-L1107"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		logic_hash = "a06d9e1190ba79b0e19cab7468f01a49359629a6feb27b7d72f3d1d52d1483d7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7c50ed29e2dd75a6a85afc43f8452794cb787ecd2061f4bf415d7038c14c523f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D4 48 FF 45 F0 48 8B 45 F0 0F B6 00 84 C0 75 DB EB 12 48 8B }

	condition:
		all of them
}