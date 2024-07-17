
rule ELASTIC_Linux_Virus_Staffcounter_D2D608A8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Virus Staffcounter (Linux.Virus.Staffcounter)"
		author = "Elastic Security"
		id = "d2d608a8-2d65-4b10-be71-0a0a6a027920"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "06e562b54b7ee2ffee229c2410c9e2c42090e77f6211ce4b9fa26459ff310315"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Virus_Staffcounter.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e30f1312eb1cbbc4faba3f67527a4e0e955b5684a1ba58cdd82a7a0f1ce3d2b9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a791024dc3064ed2e485e5c57d7ab77fc1ec14665c9302b8b572ac4d9d5d2f93"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 22 00 20 4C 69 6E 75 78 22 20 3C 00 54 6F 3A 20 22 00 20 }

	condition:
		all of them
}