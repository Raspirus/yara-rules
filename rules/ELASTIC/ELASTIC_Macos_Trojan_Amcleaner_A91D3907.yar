
rule ELASTIC_Macos_Trojan_Amcleaner_A91D3907 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Amcleaner (MacOS.Trojan.Amcleaner)"
		author = "Elastic Security"
		id = "a91d3907-5e24-46c0-90ef-ed7f46ad8792"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Amcleaner.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dc9c700f3f6a03ecb6e3f2801d4269599c32abce7bc5e6a1b7e6a64b0e025f58"
		logic_hash = "e61ceea117acf444a6b137b93d7c335c6eb8a7e13a567177ec4ea44bf64fd5c6"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "c020567fde77a72d27c9c06f6ebb103f910321cc7a1c3b227e0965b079085b49"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 40 22 4E 53 49 6D 61 67 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6A 76 64 69 5A }

	condition:
		all of them
}