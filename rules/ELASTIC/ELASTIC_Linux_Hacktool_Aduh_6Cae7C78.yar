
rule ELASTIC_Linux_Hacktool_Aduh_6Cae7C78 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Aduh (Linux.Hacktool.Aduh)"
		author = "Elastic Security"
		id = "6cae7c78-a4b4-4096-9f7c-746b1e5a1e38"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Aduh.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9c67207546ad274dc78a0819444d1c8805537f9ac36d3c53eba9278ed44b360c"
		logic_hash = "130df108de5b6cdfb9227f96301bdaa1e272d47b8cb9ad96c3aa574bf65870b2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8d7b0c1a95ec15c7d1ede5670ccd448b166467ed8eb2b4f38ebbb2c8bc323cdc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E3 51 89 E2 51 89 E1 B0 0B CD 80 31 C0 B0 01 CD }

	condition:
		all of them
}