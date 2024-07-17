rule ELASTIC_Linux_Cryptominer_Generic_1B76C066 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "1b76c066-463c-46e5-8a08-ccfc80e3f399"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L441-L459"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f60302de1a0e756e3af9da2547a28da5f57864191f448e341af1911d64e5bc8b"
		logic_hash = "be239bc14d1adf05a5c6bf2b2557551566330644a049b256a7a5c0ab9549bd06"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e33937322a1a2325539d7cdb1df13295e5ca041a513afe1d5e0941f0c66347dd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0C 14 89 0C 10 48 83 C2 04 48 83 FA 20 75 EF 48 8D 8C 24 F0 00 }

	condition:
		all of them
}