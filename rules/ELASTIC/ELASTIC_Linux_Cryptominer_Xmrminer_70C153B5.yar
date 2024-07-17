
rule ELASTIC_Linux_Cryptominer_Xmrminer_70C153B5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "70c153b5-2628-4504-8f21-2c7f0201b133"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "55b133ba805bb691dc27a5d16d3473650360c988e48af8adc017377eed07935b"
		logic_hash = "e2fc0721435c656a16e59b6747563df17f0f54a4620efc403a3bba717ccb0f38"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "51d304812e72045387b002824fdc9231d64bf4e8437c70150625c4b2aa292284"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EC 18 BA 08 00 00 00 48 8D 4C 24 08 48 89 74 24 08 BE 02 00 }

	condition:
		all of them
}