
rule ELASTIC_Windows_Shellcode_Rdi_Eee75D2C : FILE MEMORY
{
	meta:
		description = "Detects Windows Shellcode Rdi (Windows.Shellcode.Rdi)"
		author = "Elastic Security"
		id = "eee75d2c-78ef-460f-be96-4638443952fb"
		date = "2023-08-25"
		modified = "2023-11-02"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Shellcode_Rdi.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8c4de69e89dcc659d2fff52d695764f1efd7e64e0a80983ce6d0cb9eeddb806c"
		logic_hash = "18cd9be4af210686872610f832ac0ad58a48588a1226fc6093348ceb8371c6b4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2b8f840cecec00ce3112ea58e4e957e1b0754380e14a8fc8a39abc36feb077e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 81 EC 14 01 00 00 53 55 56 57 6A 6B 58 6A 65 66 89 84 24 CC 00 00 00 33 ED 58 6A 72 59 6A 6E 5B 6A 6C 5A 6A 33 }

	condition:
		all of them
}