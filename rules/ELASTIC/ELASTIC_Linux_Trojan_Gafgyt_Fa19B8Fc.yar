
rule ELASTIC_Linux_Trojan_Gafgyt_Fa19B8Fc : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "fa19b8fc-6035-4415-842f-4993411ab43e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L534-L552"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a7cfc16ec33ec633cbdcbff3c4cefeed84d7cbe9ca1f4e2a3b3e43d39291cd6b"
		logic_hash = "cddf3b9948b9bc685ff7d4c00377d0f80861169707777022297e549bd166dbf0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4f213d5d1b4a0b832ed7a6fac91bef7c29117259b775b85409e9e4c8aec2ad10"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 02 63 10 01 0F 4B 85 14 36 B0 60 53 03 4F 0D B2 05 76 02 B7 00 00 }

	condition:
		all of them
}