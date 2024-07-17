
rule ELASTIC_Windows_Trojan_Dustywarehouse_A6Cfc9F7 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Dustywarehouse (Windows.Trojan.DustyWarehouse)"
		author = "Elastic Security"
		id = "a6cfc9f7-6d4a-4904-8294-790243eca76a"
		date = "2023-08-25"
		modified = "2023-11-02"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DustyWarehouse.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8c4de69e89dcc659d2fff52d695764f1efd7e64e0a80983ce6d0cb9eeddb806c"
		logic_hash = "2b4cd9316e2fda882c95673edecb9c82a03ef4fdcc2d2e25783644cc5dfb5bf0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a0ef31535c7df8669e2b0cf38e9128e662bf64decabac5c9f3dad3a98f811033"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%4d.%2d.%2d-%2d:%2d:%2d" wide fullword
		$a2 = ":]%d-%d-%d %d:%d:%d" wide fullword
		$a3 = "\\sys.key" wide fullword
		$a4 = "[rwin]" wide fullword
		$a5 = "Software\\Tencent\\Plugin\\VAS" fullword

	condition:
		3 of them
}