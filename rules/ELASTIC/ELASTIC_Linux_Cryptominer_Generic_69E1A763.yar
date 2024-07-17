rule ELASTIC_Linux_Cryptominer_Generic_69E1A763 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "69e1a763-1e0d-4448-9bc4-769f3a36ac10"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b04d9fabd1e8fc42d1fa8e90a3299a3c36e6f05d858dfbed9f5e90a84b68bcbb"
		logic_hash = "d0dac8e2c9571d9e622c8c1250a54a7671ad1b9b00dba584c3741b714c22d8e0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9007ab73902ef9bfa69e4ddc29513316cb6aa7185986cdb10fd833157cd7d434"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 43 08 49 89 46 08 48 8B 43 10 49 89 46 10 48 85 C0 74 8A F0 83 40 }

	condition:
		all of them
}