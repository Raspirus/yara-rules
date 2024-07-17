rule ELASTIC_Linux_Trojan_Ipstorm_08Bcf61C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ipstorm (Linux.Trojan.Ipstorm)"
		author = "Elastic Security"
		id = "08bcf61c-baef-4320-885c-8f8949684dde"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ipstorm.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "503f293d84de4f2c826f81a68180ad869e0d1448ea6c0dbf09a7b23801e1a9b9"
		logic_hash = "fb2755c04b61d19788a92b8c9c1c9eb2552b62b27011e302840fdcf689b3d9b4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "348295602b1582839f6acc603832f09e9afab71731bc21742d1a638e41df6e7c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8C 24 98 00 00 00 31 D2 31 DB EB 04 48 83 C1 18 48 8B 31 48 83 79 }

	condition:
		all of them
}