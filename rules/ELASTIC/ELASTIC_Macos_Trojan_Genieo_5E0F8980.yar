
rule ELASTIC_Macos_Trojan_Genieo_5E0F8980 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Genieo (MacOS.Trojan.Genieo)"
		author = "Elastic Security"
		id = "5e0f8980-1789-4763-9e41-a521bdb3ff34"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Genieo.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6c698bac178892dfe03624905256a7d9abe468121163d7507cade48cf2131170"
		logic_hash = "76b725f6ae5755bb00d384ef2ae1511789487257d8bb7cb61b893226f03a803e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f0b5198ce85d19889052a7e33fb7cf32a7725c4fdb384ffa7d60d209a7157092"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 00 CD 01 1E 68 57 58 D7 56 7C 62 C9 27 3C C6 15 A9 3D 01 02 2F E1 69 B5 4A 11 }

	condition:
		all of them
}