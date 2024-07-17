rule ELASTIC_Linux_Cryptominer_Bulz_2Aa8Fbb5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Bulz (Linux.Cryptominer.Bulz)"
		author = "Elastic Security"
		id = "2aa8fbb5-b392-49fc-8f0f-12cd06d534e2"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Bulz.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "21d8bec73476783e01d2a51a99233f186d7c72b49c9292c42e19e1aa6397d415"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c8fbeae6cf935fe629c37abc4fdcda2c80c1b19fc8b6185a58decead781e1321"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FE D7 C5 D9 72 F2 09 C5 E9 72 D2 17 C5 E9 EF D4 C5 E9 EF D6 C5 C1 }

	condition:
		all of them
}