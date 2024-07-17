rule ELASTIC_Linux_Cryptominer_Bulz_0998F811 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Bulz (Linux.Cryptominer.Bulz)"
		author = "Elastic Security"
		id = "0998f811-7be3-4d46-9dcb-1e8a0f19bab5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Bulz.yar#L20-L37"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "178f6c42582dd99cc5418388d020d4d76f2a9204297a673359fe0a300121c35b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c8a83bc305998cb6256b004e9d8ce6d5d1618b107e42be139b73807462b53c31"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 79 70 E4 39 C5 F9 70 C9 4E C5 91 72 F0 12 C5 F9 72 D0 0E C5 91 }

	condition:
		all of them
}