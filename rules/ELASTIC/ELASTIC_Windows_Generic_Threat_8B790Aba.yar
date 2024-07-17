
rule ELASTIC_Windows_Generic_Threat_8B790Aba : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "8b790aba-02b4-4c71-a51e-3a56ea5728ec"
		date = "2024-01-09"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L813-L832"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ec98bfff01d384bdff6bbbc5e17620b31fa57c662516157fd476ef587b8d239e"
		logic_hash = "8a0b2af3d0c95466ca138dfcc3d6f6a702ec92f5cd4f791b1200c79ffd973840"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "8581397f15b9985bafa5248f0e7f044bf80c82e441d2216dc0976c806f658d2e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 7A 66 62 50 4A 64 73 72 78 77 7B 7B 79 55 36 46 42 50 4A 3F 20 2E 6E 3E 36 65 73 7A }
		$a2 = { 50 36 7B 77 64 71 79 64 46 4A 73 64 79 62 45 7A 77 63 62 64 }

	condition:
		all of them
}