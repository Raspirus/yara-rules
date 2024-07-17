rule ELASTIC_Macos_Virus_Vsearch_0Dd3Ec6F : FILE MEMORY
{
	meta:
		description = "Detects Macos Virus Vsearch (MacOS.Virus.Vsearch)"
		author = "Elastic Security"
		id = "0dd3ec6f-815f-40e1-bd53-495e0eae8196"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Virus_Vsearch.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "17a467b000117ea6c39fbd40b502ac9c7d59a97408c2cdfb09c65b2bb09924e5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8adbd06894e81dc09e46d8257d4e5fcd99e714f54ffb36d5a8d6268ea25d0bd6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 2F 00 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6D 00 2F 4D 61 63 69 6E 74 6F 73 }

	condition:
		all of them
}