
rule ELASTIC_Linux_Trojan_Tsunami_0Fa3A6E9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "0fa3a6e9-89f3-4bc8-8dc1-e9ccbeeb836d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "40a15a186373a062bfb476b37a73c61e1ba84e5fa57282a7f9ec0481860f372a"
		logic_hash = "970062e909ffe5356b750605f2c44a6e893949bc5bc71be3ea98b16e51629d4d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fed796c5275e2e91c75dcdbf73d0c0ab37591115989312c6f6c5adcd138bc91f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EC 8B 55 EC C1 FA 10 0F B7 45 EC 01 C2 89 55 EC 8B 45 EC C1 }

	condition:
		all of them
}