rule ELASTIC_Linux_Cryptominer_Malxmr_21D0550B : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "21d0550b-4f15-4481-ba9c-2be26ea8f81a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
		logic_hash = "c9a12eee281b1e944b5572142c5e18ff087989f45026a94268df22d483210178"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5b556d2e3e48fda57c741c4c7b9efb72aad579e5055df366cdb9cfa38e496494"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 3B 31 C0 48 83 C9 FF 48 89 EE F2 AE 48 8B 3B 48 F7 D1 48 FF C9 }

	condition:
		all of them
}