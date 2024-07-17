rule ELASTIC_Linux_Trojan_Generic_7A95Ef79 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "7a95ef79-3df5-4f7a-a8ba-00577473b288"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L141-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f59340a740af8f7f4b96e3ea46d38dbe81f2b776820b6f53b7028119c5db4355"
		logic_hash = "6da43e4bab6b2024b49dfc943f099fb21c06d8d4a082a05594b07cb55989183c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "aadec0fa964f94afb725a568dacf21e80b80d359cc5dfdd8d028aaece04c7012"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 1C 8B 54 24 20 8B 74 24 24 CD 80 5E 5A 59 5B C3 }

	condition:
		all of them
}