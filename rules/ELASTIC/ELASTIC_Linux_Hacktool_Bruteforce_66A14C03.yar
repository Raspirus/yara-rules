
rule ELASTIC_Linux_Hacktool_Bruteforce_66A14C03 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Bruteforce (Linux.Hacktool.Bruteforce)"
		author = "Elastic Security"
		id = "66a14c03-f4a3-4b24-a5db-5a9235334e37"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Bruteforce.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a2d8e2c34ae95243477820583c0b00dfe3f475811d57ffb95a557a227f94cd55"
		logic_hash = "c8b2925c2e3f95e78f117ddd52e208d143d19ee75e9283f7f15d10e930eaac5f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "255c1a2e781ff7f330c09b3c82f08db110579f77ccef8780d03e9aa3eec86607"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 8B 4C 24 08 78 3D 48 8B 44 24 30 48 29 C8 48 89 4D 08 48 89 }

	condition:
		all of them
}