
rule ELASTIC_Linux_Trojan_Mirai_C5430Ff9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "c5430ff9-af40-4653-94c3-4651a5e9331e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L637-L655"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5676773882a84d0efc220dd7595c4594bc824cbe3eeddfadc00ac3c8e899aa77"
		logic_hash = "8c385980560cd4b24e703744b57a9d5ea1bca8fbeea066e98dd4b40009e56104"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a19dcb00fc5553d41978184cc53ef93c36eb9541ea19c6c50496b4e346aaf240"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 00 FC F3 A6 0F 97 C2 0F 92 C0 38 C2 75 29 83 EC 08 8B }

	condition:
		all of them
}