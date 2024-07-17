rule ELASTIC_Linux_Cryptominer_Generic_E1Ff020A : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "e1ff020a-446c-4537-8cc3-3bcc56ba5a99"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L321-L339"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5b611898f1605751a3d518173b5b3d4864b4bb4d1f8d9064cc90ad836dd61812"
		logic_hash = "be801989b9770f3b70217bd5f13795b5dd0b516209f631d900b6647e0afe8d98"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "363872fe6ef89a0f4c920b1db4ac480a6ae70e80211200b73a804b43377fff01"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F B6 4F 3D 0B 5C 24 F4 41 C1 EB 10 44 0B 5C 24 }

	condition:
		all of them
}