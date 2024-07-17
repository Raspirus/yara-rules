rule ELASTIC_Linux_Trojan_Mobidash_601352Dc : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "601352dc-13b6-4c3f-a013-c54a50e46820"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L80-L98"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5714e130075f4780e025fb3810f58a63e618659ac34d12abe211a1b6f2f80269"
		logic_hash = "adeeea73b711fc867b88775c06a14011380118ed85691660ba771381e51160e3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "acfca9259360641018d2bf9ba454fd5b65224361933557e007ab5cfb12186cd7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F6 74 14 48 8B BC 24 D0 00 00 00 48 8B 07 48 8B 80 B8 00 00 00 }

	condition:
		all of them
}