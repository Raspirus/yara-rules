rule ELASTIC_Macos_Trojan_Amcleaner_8Ce3Fea8 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Amcleaner (MacOS.Trojan.Amcleaner)"
		author = "Elastic Security"
		id = "8ce3fea8-3cc7-4c59-b07c-a6dda0bb6b85"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Amcleaner.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
		logic_hash = "08c4b5b4afefbf1ee207525f9b28bc7eed7b55cb07f8576fddfa0bbe95002769"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e156d3c7a55cae84481df644569d1c5760e016ddcc7fd05d0f88fa8f9f9ffdae"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 54 40 22 4E 53 54 61 62 6C 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6B 54 70 51 }

	condition:
		all of them
}