
rule ELASTIC_Linux_Trojan_Generic_D8953Ca0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "d8953ca0-f1f1-4d76-8c80-06f16998ba03"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L241-L259"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "552753661c3cc7b3a4326721789808482a4591cb662bc813ee50d95f101a3501"
		logic_hash = "cbc1a60a1d9525f7230336dff07f56e6a0b99e7c70c99d3f4363c06ed0071716"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "16ab55f99be8ed2a47618978a335a8c68369563c0a4d0a7ff716b5d4c9e0785c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 5B 9C 9C 9C 9C 5C 5D 5E 5F 9C 9C 9C 9C B1 B2 B3 B4 9C 9C 9C 9C }

	condition:
		all of them
}