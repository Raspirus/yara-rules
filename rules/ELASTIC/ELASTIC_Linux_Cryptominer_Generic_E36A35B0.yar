rule ELASTIC_Linux_Cryptominer_Generic_E36A35B0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "e36a35b0-cb38-4d2d-bca2-f3734637faa8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L721-L739"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ab6d8f09df67a86fed4faabe4127cc65570dbb9ec56a1bdc484e72b72476f5a4"
		logic_hash = "0572f584746a2af6f545798b25445fd4e764a9eecc01b7476e5c1af631eb314a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0ee42ff704c82ee6c2bc0408cccb77bcbae8d4405bb1f405ee09b093e7a626c0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 71 F2 08 66 0F EF C1 66 0F EF D3 66 0F 7F 44 24 60 66 0F 7F 54 }

	condition:
		all of them
}