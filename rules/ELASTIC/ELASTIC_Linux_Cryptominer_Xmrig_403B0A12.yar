rule ELASTIC_Linux_Cryptominer_Xmrig_403B0A12 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "403b0a12-8475-4e28-960b-ef33eabf0fcf"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L119-L137"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "54d806b3060404ccde80d9f3153eebe8fdda49b6e8cdba197df0659c6724a52d"
		logic_hash = "5b7662124eb980b11f88a50665292e7a405595f7ad85c5c448dd087ea096689a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "785ac520b9f2fd9c6b49d8a485118eee7707f0fa0400b3db99eb7dfb1e14e350"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 28 03 1C C3 0C 00 C0 00 60 83 1C A7 71 00 00 00 68 83 5C D7 }

	condition:
		all of them
}