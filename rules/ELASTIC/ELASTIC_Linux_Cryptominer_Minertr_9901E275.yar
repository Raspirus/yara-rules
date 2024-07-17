
rule ELASTIC_Linux_Cryptominer_Minertr_9901E275 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Minertr (Linux.Cryptominer.Minertr)"
		author = "Elastic Security"
		id = "9901e275-3053-47ea-8c36-6c9271923b64"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Minertr.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f77246a93782fd8ee40f12659f41fccc5012a429a8600f332c67a7c2669e4e8f"
		logic_hash = "a18e0763fe9aec6d89b39cefb872b1751727e2d88ec4733b9c8b443b83219763"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f27e404d545f3876963fd6174c4235a4fe4f69d53fe30a2d29df9dad6d97b7f7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 56 41 55 41 54 55 53 48 83 EC 78 48 89 3C 24 89 F3 89 74 }

	condition:
		all of them
}