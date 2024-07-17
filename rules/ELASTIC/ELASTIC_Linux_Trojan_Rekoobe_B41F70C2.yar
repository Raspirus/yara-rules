rule ELASTIC_Linux_Trojan_Rekoobe_B41F70C2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rekoobe (Linux.Trojan.Rekoobe)"
		author = "Elastic Security"
		id = "b41f70c2-abe4-425a-952f-5e0c9e572a76"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rekoobe.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "19c1a54279be1710724fc75a112741575936fe70379d166effc557420da714cd"
		logic_hash = "02de55c537da1cc03af26a171c768ad87984e45983c3739f90ad9983c70e7ccf"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "396fcb4333abe90f4c228d06c20eeff40f91e25fde312cc7760d999da0aa1027"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E2 10 4D 31 D1 0F B6 D6 48 8B 14 D1 48 C1 E2 08 4C 31 CA 48 89 }

	condition:
		all of them
}