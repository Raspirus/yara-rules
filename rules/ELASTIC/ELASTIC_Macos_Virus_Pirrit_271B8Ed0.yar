
rule ELASTIC_Macos_Virus_Pirrit_271B8Ed0 : FILE MEMORY
{
	meta:
		description = "Detects Macos Virus Pirrit (MacOS.Virus.Pirrit)"
		author = "Elastic Security"
		id = "271b8ed0-937a-4be6-aecb-62535b5aeda7"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Virus_Pirrit.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7feda05d41b09c06a08c167c7f4dde597ac775c54bf0d74a82aa533644035177"
		logic_hash = "cb77f6df1403afbc7f45d30551559b6de7eb1c3434778b46d31754da0a1b1f10"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "12b09b2e3a43905db2cfe96d0fd0e735cfc7784ee7b03586c5d437d7c6a1b422"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 4A 6A 00 00 32 80 35 44 6A 00 00 75 80 35 3E 6A 00 00 1F 80 35 38 6A 00 00 }

	condition:
		all of them
}