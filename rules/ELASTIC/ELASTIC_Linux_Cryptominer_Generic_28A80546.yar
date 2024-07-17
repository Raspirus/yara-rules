rule ELASTIC_Linux_Cryptominer_Generic_28A80546 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "28a80546-ae74-4616-8896-50f54da66650"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "96cc225cf20240592e1dcc8a13a69f2f97637ed8bc89e30a78b8b2423991d850"
		logic_hash = "120e9f7cad0fc8aebd843374c0edca8cbb701882ab55a7f24aced1d80d8cd697"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7f49f04ba36e7ff38d313930c469d64337203a60792f935a3548cee176ae9523"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 72 59 D4 B5 63 E2 4D B6 08 EF E8 0A 3A B1 AD 1B 61 6E 7C 65 D1 }

	condition:
		all of them
}