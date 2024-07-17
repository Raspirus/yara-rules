rule ELASTIC_Linux_Cryptominer_Xmrminer_02D19C01 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "02d19c01-51e9-4a46-a06b-d5f7e97285d9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L139-L157"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b6df662f5f7566851b95884c0058e7476e49aeb7a96d2aa203393d88e584972f"
		logic_hash = "43a1dc49bf75cd13637c37290d47b4d6fc1b2c2ac252b64725c0c64e1dd745c6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "724bbc2910217bcac457e6ba0c0848caf38e12f272b0104ade1c7bc57dc85c27"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4C 8D 7E 15 41 56 41 55 41 54 41 BB 03 00 00 00 55 53 48 89 FB 48 }

	condition:
		all of them
}