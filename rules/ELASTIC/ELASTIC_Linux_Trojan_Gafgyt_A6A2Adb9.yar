rule ELASTIC_Linux_Trojan_Gafgyt_A6A2Adb9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "a6a2adb9-9d54-42d4-abed-5b30d8062e97"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L100-L118"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		logic_hash = "8f5fc4cb1ad51178701509a44a793e119fe7e7fad97eafcac8be14fce64e3b7b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cdd0bb9ce40a000bb86b0c76616fe71fb7dbb87a044ddd778b7a07fdf804b877"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CC 01 C2 89 55 B4 8B 45 B4 C9 C3 55 48 89 E5 48 81 EC 90 00 }

	condition:
		all of them
}