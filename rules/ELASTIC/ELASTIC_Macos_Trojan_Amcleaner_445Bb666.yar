rule ELASTIC_Macos_Trojan_Amcleaner_445Bb666 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Amcleaner (MacOS.Trojan.Amcleaner)"
		author = "Elastic Security"
		id = "445bb666-1707-4ad9-a409-4a21de352957"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Amcleaner.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
		logic_hash = "664829ff761186ec8f3055531b5490b7516756b0aa9d0183d4c17240a5ca44c4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "355c7298a4148be3b80fd841b483421bde28085c21c00d5e4a42949fd8026f5b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 10 A0 5B 15 57 A8 8B 17 02 F9 A8 9B E8 D5 8C 96 A7 48 42 91 E5 EC 3D C8 AC 52 }

	condition:
		all of them
}