
rule ELASTIC_Linux_Trojan_Gafgyt_859042A0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "859042a0-a424-4c83-944b-ed182b342998"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L951-L969"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "41615d3f3f27f04669166fdee3996d77890016304ee87851a5f90804d6d4a0b0"
		logic_hash = "b8daa4a136a6511472703687fe56fbca2bd005a1373802a46c8d211b6d039d75"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a27bcaa16edceda3dc5a80803372c907a7efd00736c7859c5a9d6a2cf56a8eec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 A8 48 83 C0 01 48 89 45 C0 EB 05 48 83 45 C0 01 48 8B 45 C0 0F }

	condition:
		all of them
}