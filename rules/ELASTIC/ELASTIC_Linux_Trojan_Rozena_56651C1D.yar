rule ELASTIC_Linux_Trojan_Rozena_56651C1D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rozena (Linux.Trojan.Rozena)"
		author = "Elastic Security"
		id = "56651c1d-548e-4a51-8f1c-e4add55ec14f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rozena.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "997684fb438af3f5530b0066d2c9e0d066263ca9da269d6a7e160fa757a51e04"
		logic_hash = "a6d283b0c398cb1004defe7f5669f912112262e5aaf677ae4ca7fd15565cb988"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a86abe550b5c698a244e1c0721cded8df17d2c9ed0ee764d6dea36acf62393de"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E1 95 68 A4 1A 70 C7 57 FF D6 6A 10 51 55 FF D0 68 A4 AD }

	condition:
		all of them
}