rule ELASTIC_Linux_Trojan_Mirai_Fa48B592 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "fa48b592-8d80-45af-a3e4-232695b8f5dd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L891-L909"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c9e33befeec133720b3ba40bb3cd7f636aad80f72f324c5fe65ac7af271c49ee"
		logic_hash = "5648bcc96b1fdd1529b4b8765b1738594d0d61f7880b763e803cd89bd117e96b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8838d2752b310dbf7d12f6cf023244aaff4fdf5b55cf1e3b71843210df0fcf88"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 31 C0 BA 01 00 00 00 B9 01 00 00 00 03 04 24 89 D7 31 D2 F7 F7 0F }

	condition:
		all of them
}