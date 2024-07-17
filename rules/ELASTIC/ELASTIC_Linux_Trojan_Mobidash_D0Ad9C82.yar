
rule ELASTIC_Linux_Trojan_Mobidash_D0Ad9C82 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "d0ad9c82-718f-43d1-a764-9be83893f9b8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		logic_hash = "8351cb61f5b712c65962e734a7c29271fa4805720e14b6badc9bc1c0364778f8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ef6b2f9383c137eb4adfe0a6322a0e5d71cb4a5712f1be26fe687144933cbbc8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 48 8D 64 24 F8 48 8B 07 FF 90 F8 00 }

	condition:
		all of them
}