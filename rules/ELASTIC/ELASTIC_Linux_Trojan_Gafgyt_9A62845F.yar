rule ELASTIC_Linux_Trojan_Gafgyt_9A62845F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "9a62845f-6311-49ae-beac-f446b2909d9c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1167-L1185"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f67f8566beab9d7494350923aceb0e76cd28173bdf2c4256e9d45eff7fc8cb41"
		logic_hash = "b3ab125c8bfb5b7a0be0e92cf5a50057e403ab3597698ec2e7a8bafa0d3a8b80"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2ccc813c5efed35308eb2422239b5b83d051eca64b7c785e66d602b13f8bd9b4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 83 F8 20 7F 1E 83 7D 08 07 75 33 8B 45 0C 83 C0 18 8B 00 83 }

	condition:
		all of them
}