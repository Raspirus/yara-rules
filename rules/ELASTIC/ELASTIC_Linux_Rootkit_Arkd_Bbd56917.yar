rule ELASTIC_Linux_Rootkit_Arkd_Bbd56917 : FILE MEMORY
{
	meta:
		description = "Detects Linux Rootkit Arkd (Linux.Rootkit.Arkd)"
		author = "Elastic Security"
		id = "bbd56917-aeab-4e73-b85b-adc41fc7ffe4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Rootkit_Arkd.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e0765f0e90839b551778214c2f9ae567dd44838516a3df2c73396a488227a600"
		logic_hash = "5e1ce9c37d92222e21b43f9e5f3275a70c6e8eb541c3762f9382c5d5c72fb50d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "73c8b2685b6b568575afca3c3c2fe2095d94f2040f4a1207974fe77bbb657163"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 7D 0B B8 FF FF FF FF EB 11 8D 74 26 00 39 C1 7F 04 31 C0 EB 05 B8 01 00 }

	condition:
		all of them
}