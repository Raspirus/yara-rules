rule ELASTIC_Linux_Trojan_Ngioweb_E2377400 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ngioweb (Linux.Trojan.Ngioweb)"
		author = "Elastic Security"
		id = "e2377400-8884-42fb-b524-9cdf836dac3a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ngioweb.yar#L141-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b88daf00a0e890b6750e691856b0fe7428d90d417d9503f62a917053e340228b"
		logic_hash = "71276698d1bdb9bc494fe6f1aa9755940583331836abc490e0b5ac3454d35de6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "531a8fcb1c097f72cb9876a35ada622dd1129f90515d84b4c245920602419698"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EC 08 8B 5C 24 10 8B 43 20 85 C0 74 72 83 7B 28 00 74 6C 83 7B }

	condition:
		all of them
}