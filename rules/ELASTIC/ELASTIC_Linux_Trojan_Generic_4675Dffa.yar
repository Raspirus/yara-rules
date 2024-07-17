
rule ELASTIC_Linux_Trojan_Generic_4675Dffa : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "4675dffa-0536-4a4d-bedb-f8c7fa076168"
		date = "2023-07-28"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L301-L320"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "43e14c9713b1ca1f3a7f4bcb57dd3959d3a964be5121eb5aba312de41e2fb7a6"
		logic_hash = "d2865a869d0cf0bf784106fe6242a4c7f58e58a43c4d4ae0241b10569810904d"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "7aa556e481694679ce0065bcaaa4d35e2c2382326681f03202b68b1634db08ab"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = ", i = , not , val ./zzzz.local.onion"
		$a2 = { 61 74 20 20 25 76 3D 25 76 2C 20 28 63 6F 6E 6E 29 20 28 73 63 61 6E 20 20 28 73 63 }

	condition:
		all of them
}