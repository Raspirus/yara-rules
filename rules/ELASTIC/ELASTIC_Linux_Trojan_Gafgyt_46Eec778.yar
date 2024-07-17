
rule ELASTIC_Linux_Trojan_Gafgyt_46Eec778 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "46eec778-7342-4ef7-adac-35bc0cdb9867"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L574-L592"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
		logic_hash = "08e77a31005e14a06197857301e22d20334c1f2ef7fc06a4208643438377f4c4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2602371a40171870b1cf024f262e95a2853de53de39c3a6cd3de811e81dd3518"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 01 45 F8 48 83 45 E8 02 83 6D C8 02 83 7D C8 01 7F E4 83 7D }

	condition:
		all of them
}