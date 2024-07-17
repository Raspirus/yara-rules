
rule ELASTIC_Linux_Cryptominer_Xmrminer_C6218E30 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "c6218e30-1a49-46ea-aac8-5f0f652156c5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L199-L217"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b43ddd8e355b0c538c123c43832e7c8c557e4aee9e914baaed0866ee5d68ee55"
		logic_hash = "3efbc3cb1591a9340df10640b411a9ab4c41e0aa26c1677d9def8b82e4c246f4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c3171cf17ff3b0ca3d5d62fd4c2bd02a4e0a8616a84ea5ef9e78307283e4a360"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { AC 24 B0 00 00 00 48 89 FA 66 0F EF DD 48 C1 E2 20 66 41 0F }

	condition:
		all of them
}