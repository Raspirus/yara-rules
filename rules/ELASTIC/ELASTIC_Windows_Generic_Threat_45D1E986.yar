rule ELASTIC_Windows_Generic_Threat_45D1E986 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "45d1e986-78fb-4a83-97f6-2b40c657e709"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1159-L1177"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fd159cf2f9bd48b0f6f5958eef8af8feede2bcbbea035a7e56ce1ff72d3f47eb"
		logic_hash = "d53a4d189b9a49f9b6477e12bce0d41e62827306d1df79e6494ab67669d84f35"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "facb67b78cc4d6cf5d141fd7153d331209e5ce46f29c0078c7e5683165c37057"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 45 00 06 00 00 00 08 28 45 00 09 00 00 00 14 28 45 00 09 00 00 00 20 28 45 00 07 00 00 00 28 28 45 00 0A 00 00 00 34 28 45 00 0B 00 00 00 40 28 45 00 09 00 00 00 5B 81 45 00 00 00 00 00 4C }

	condition:
		all of them
}