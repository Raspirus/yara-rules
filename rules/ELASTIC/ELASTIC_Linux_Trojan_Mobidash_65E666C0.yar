rule ELASTIC_Linux_Trojan_Mobidash_65E666C0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "65e666c0-4eb7-4411-8743-053b6c0ec1d6"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L119-L137"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "19f9b5382d3e8e604be321aefd47cb72c2337a170403613b853307c266d065dd"
		logic_hash = "2d2bec8f89986b19bf1c806b6654405ac6523f49aeafd759b7631d9587d780c8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "92b7de293a7e368d0e92a6e2061e9277e7b285851322357808a04f8c203b20d0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4C 8B 44 24 08 48 89 DF 48 8B 14 24 48 8D 64 24 18 5B 4C 89 E6 48 }

	condition:
		all of them
}