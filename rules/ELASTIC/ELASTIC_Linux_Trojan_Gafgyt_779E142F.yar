rule ELASTIC_Linux_Trojan_Gafgyt_779E142F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "779e142f-b867-46e6-b1fb-9105976f42fd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L892-L910"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		logic_hash = "80ba5a1cf333fafc6a1d7823ca4a8d5c30c1c07a01d6d681c22dd29e197089f1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "83377b6fa77fda4544c409487d2d2c1ddcef8f7d4120f49a18888c7536f3969f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EC 8B 45 E8 83 E0 02 85 C0 74 07 C7 45 D8 30 00 00 00 8B 45 E8 83 }

	condition:
		all of them
}