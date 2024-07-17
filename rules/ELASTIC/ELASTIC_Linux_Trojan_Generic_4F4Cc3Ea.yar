rule ELASTIC_Linux_Trojan_Generic_4F4Cc3Ea : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "4f4cc3ea-a906-4fce-a482-d762ab8995b8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "32e25641360dbfd50125c43754cd327cf024f1b3bfd75b617cdf8a17024e2da5"
		logic_hash = "9eb0d93b8c1a579ca8362d033edecbbe6a9ade82f6ae5688c183b97ed7b97faa"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "d85dac2bd81925f5d8c90c11047c631c1046767cb6649cd266c3a143353b6c12"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4A 4E 49 20 55 4E 50 41 43 4B 20 44 45 58 20 53 54 41 52 54 20 }

	condition:
		all of them
}