rule ELASTIC_Linux_Trojan_Gafgyt_Cf84C9F2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "cf84c9f2-7435-4faf-8c5f-d14945ffad7a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L912-L930"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		logic_hash = "9af164ece7e7e0f33dc32f18735a8f655593ae6cde34e05108f3221b71aa8676"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bb766b356c3e8706740e3bb9b4a7171d8eb5137e09fc7ab6952412fa55e2dcfc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 48 89 E5 48 83 EC 30 48 89 7D E8 89 75 E4 89 55 E0 C7 45 F8 01 00 }

	condition:
		all of them
}