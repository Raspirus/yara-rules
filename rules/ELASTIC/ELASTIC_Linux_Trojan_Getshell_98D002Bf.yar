rule ELASTIC_Linux_Trojan_Getshell_98D002Bf : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Getshell (Linux.Trojan.Getshell)"
		author = "Elastic Security"
		id = "98d002bf-63b7-4d11-98ef-c3127e68d59c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Getshell.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "97b7650ab083f7ba23417e6d5d9c1d133b9158e2c10427d1f1e50dfe6c0e7541"
		logic_hash = "358575f55910b060bde94bbc55daa9650a43cf1470b77d1842ddcaa8b299700a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b7bfec0a3cfc05b87fefac6b10673491b611400edacf9519cbcc1a71842e9fa3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { B2 6A B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }

	condition:
		all of them
}