
rule ELASTIC_Linux_Hacktool_Bruteforce_Bad95Bd6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Bruteforce (Linux.Hacktool.Bruteforce)"
		author = "Elastic Security"
		id = "bad95bd6-94a9-4abf-9d3b-781f0b79c5ce"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Bruteforce.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8e8be482357ebddc6ac3ea9ee60241d011063f7e558a59e6bd119e72e4862024"
		logic_hash = "8001e6503baeb52c66c9b30026544913270085406a1fe4c45d14629811d36d5f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "10698122ff9fe06b398307ec15ad4f5bb519285e1eaad97011abf0914f1e7afd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 73 65 6E 64 6D 6D 73 67 00 66 70 75 74 73 00 6D 65 6D 63 70 79 00 }

	condition:
		all of them
}