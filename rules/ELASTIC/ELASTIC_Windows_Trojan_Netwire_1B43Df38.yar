rule ELASTIC_Windows_Trojan_Netwire_1B43Df38 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Netwire (Windows.Trojan.Netwire)"
		author = "Elastic Security"
		id = "1b43df38-886e-4f58-954a-a09f30f19907"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Netwire.yar#L22-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
		logic_hash = "bb0eb1c1969bc1416e933822843293c5d41bf9bc3d402fa5dbdc3cdf2f4b394a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4142ea14157939dc23b8d1f5d83182aef3a5877d2506722f7a2706b7cb475b76"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
		$a2 = "\\Login Data"
		$a3 = "SOFTWARE\\NetWire" fullword

	condition:
		2 of them
}