rule ELASTIC_Windows_Trojan_Bumblebee_35F50Bea : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bumblebee (Windows.Trojan.Bumblebee)"
		author = "Elastic Security"
		id = "35f50bea-c497-4cc6-b915-8ad3aca7bee6"
		date = "2022-04-28"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bumblebee.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9fff05a5aa9cbbf7d37bc302d8411cbd63fb3a28dc6f5163798ae899b9edcda6"
		logic_hash = "9f22b1b7f9e2d7858738d02730ef5477f8d430ad3606ebf4ac8b01314fdc9c46"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f2e07a9b7d143ca13852f723e7d0bd55365d6f8b5d9315b7e24b7f1101010820"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 43 28 45 33 D2 4D 8D 0C 00 44 88 54 24 20 66 48 0F 7E C9 66 0F }
		$a2 = { 31 DA 48 31 C7 45 ?? C9 B9 E8 03 C7 45 ?? 00 00 BA 01 C7 45 ?? 00 00 00 48 C7 45 ?? B8 88 77 66 C7 45 ?? 55 44 33 22 C7 45 ?? 11 FF D0 EB C6 45 }

	condition:
		any of them
}