rule ELASTIC_Linux_Trojan_Marut_47Af730D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Marut (Linux.Trojan.Marut)"
		author = "Elastic Security"
		id = "47af730d-1e03-4d27-9661-84fb12b593bd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Marut.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "048ce8059be6697c5f507fb1912ac2adcedab87c75583dd84700984e6d0d81e6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4429ef9925aff797ab973f9a5b0efc160a516f425e3b024f22e5a5ddad26c341"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 89 34 24 FF D1 8B 44 24 0C 0F B6 4C 24 04 8B 54 24 08 85 D2 }

	condition:
		all of them
}