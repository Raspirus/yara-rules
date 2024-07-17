
rule ELASTIC_Linux_Trojan_Mirai_402Adc45 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "402adc45-6279-44a6-b766-24706b0328fe"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L657-L675"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
		logic_hash = "dab879d57507d5e119ddf4ce6ed33570c74f185a2260e97a7ec1d6c844943e5d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "01b88411c40abc65c24d7a335027888c0cf48ad190dd3fa1b8e17d086a9b80a0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C3 EB DF 5A 5B 5D 41 5C 41 5D C3 41 57 41 56 41 55 41 54 55 53 48 }

	condition:
		all of them
}