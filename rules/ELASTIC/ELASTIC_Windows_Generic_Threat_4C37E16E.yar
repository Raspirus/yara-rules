
rule ELASTIC_Windows_Generic_Threat_4C37E16E : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "4c37e16e-b7ca-449a-a09f-836706b2f66a"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2922-L2941"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d83a8ed5e192b3fe9d74f3a9966fa094d23676c7e6586c9240d97c252b8e4e74"
		logic_hash = "dabac8aa6a3f4d4bd726161fc6573ca9de4088e7d818c3cf33cafc91f680e7aa"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "9fbd2883fb0140de50df755f7099a0dc3cf377ee350710108fef96c912f43460"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 2E 3F 41 56 43 44 72 6F 70 41 70 69 40 40 }
		$a2 = { 2D 2D 77 77 6A 61 75 67 68 61 6C 76 6E 63 6A 77 69 61 6A 73 2D 2D }

	condition:
		all of them
}