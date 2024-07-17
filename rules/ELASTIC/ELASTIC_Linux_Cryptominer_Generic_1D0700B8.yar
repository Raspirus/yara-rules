rule ELASTIC_Linux_Cryptominer_Generic_1D0700B8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "1d0700b8-1bc0-4da2-a903-9d78e79e71d8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L641-L659"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
		logic_hash = "a24264cb071d269c82718aed5bc5c6c955e1cb2c7a63fe74d4033bfa6adf8385"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "19853be803f82e6758554a57981e1b52c43a017ab88242c42a7c39f6ead01cf3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 30 42 30 42 00 22 22 03 5C DA 10 00 C0 00 60 43 9C 64 48 00 00 00 }

	condition:
		all of them
}