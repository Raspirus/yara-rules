
rule ELASTIC_Windows_Trojan_Bitrat_54916275 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bitrat (Windows.Trojan.Bitrat)"
		author = "Elastic Security"
		id = "54916275-2a0f-4966-956d-7122a4aea9c8"
		date = "2022-08-29"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bitrat.yar#L25-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d3b2c410b431c006c59f14b33e95c0e44e6221b1118340c745911712296f659f"
		logic_hash = "4c66f79f4bf6bde49bfb9208e6dc1d3b5d041927565e7302381838b0f32da6f4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8758b1a839ff801170f6d4ae9186a69af6370f8081defdd25b62e50a3ddcffef"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 6A 10 68 50 73 78 00 E8 5F 4D 02 00 8B 7D 08 85 FF 75 0D FF 15 1C 00 6E 00 50 FF 15 68 03 6E 00 }

	condition:
		all of them
}