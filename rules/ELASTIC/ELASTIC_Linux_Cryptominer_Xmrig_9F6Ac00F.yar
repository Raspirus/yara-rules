
rule ELASTIC_Linux_Cryptominer_Xmrig_9F6Ac00F : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "9f6ac00f-1562-4be1-8b54-bf9a89672b0e"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L198-L216"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9cd58c1759056c0c5bbd78248b9192c4f8c568ed89894aff3724fdb2be44ca43"
		logic_hash = "9fa8e7be5c35c9a649c42613d0d5d5cecff3d9c3e9a572e4be1ca661876748a5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "77b171a3099327a5edb59b8f1b17fb3f415ab7fd15beabcd3b53916cde206568"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { B8 31 75 00 00 83 E3 06 09 D9 01 C9 D3 F8 89 C1 }

	condition:
		all of them
}