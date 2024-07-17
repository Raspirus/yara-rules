
rule ELASTIC_Linux_Cryptominer_Xmrminer_B17A7888 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "b17a7888-dc12-4bb4-bc77-558223814e8b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L219-L237"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "65c9fdd7c559554af06cd394dcebece1bc0fdc7dd861929a35c74547376324a6"
		logic_hash = "a7f6daa5c42d186d2c5a027fdb35b45287c3564a7b57b8a2f53659e6ca90602a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2b11457488e6098d777fb0d8f401cf10af5cd48e05248b89cb9e377d781b516c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D4 FF C5 55 F4 C9 C5 F5 D4 CD C4 41 35 D4 C9 C5 B5 D4 C9 C5 C5 }

	condition:
		all of them
}