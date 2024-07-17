
rule ELASTIC_Linux_Trojan_Sshdkit_18A0B82A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sshdkit (Linux.Trojan.Sshdkit)"
		author = "Elastic Security"
		id = "18a0b82a-94ff-4328-bfa7-25034f170522"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sshdkit.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "003245047359e17706e4504f8988905a219fcb48865afea934e6aafa7f97cef6"
		logic_hash = "4b7a78ebf3c114809148cc9855379b2e63c959966272ad45759838d570b42016"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9bd28a490607b75848611389b39cf77229cfdd1e885f23c5439d49773924ce16"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 06 2A CA 37 F2 31 18 0E 2F 47 CD 87 9D 16 3F 6D }

	condition:
		all of them
}