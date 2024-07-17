rule ELASTIC_Linux_Trojan_Mirai_Ab073861 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "ab073861-38df-4a39-ab81-8451b6fab30c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L950-L968"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "175444a9c9ca78565de4b2eabe341f51b55e59dec00090574ee0f1875422cbac"
		logic_hash = "251b92c4fec9d113025c6869c279247a3dd16ee094c8861fe43a33f87132bf75"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "37ab5e3ccc9a91c885bff2b1b612efbde06999e83ff5c5cd330bd3a709a831f5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { AC 00 00 00 54 60 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }

	condition:
		all of them
}