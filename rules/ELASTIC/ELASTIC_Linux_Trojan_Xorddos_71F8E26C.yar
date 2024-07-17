rule ELASTIC_Linux_Trojan_Xorddos_71F8E26C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "71f8e26c-d0ff-49e8-9c20-8df9149e8843"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L337-L355"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "13f873f83b84a0d38eb3437102f174f24a0ad3c5a53b83f0ee51c62c29fb1465"
		logic_hash = "f9f2f22acd4f52cc313e3ecf425604651e0b8c78e33480d4d05bae5b8c9661fb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dbd1275bd01fb08342e60cb0c20adaf42971ed6ee0f679fedec9bc6967ecc015"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 8D 64 24 04 1B 07 87 DA 8B 5D F4 52 87 DA 5B 83 C2 03 52 8B 54 }

	condition:
		all of them
}