rule ELASTIC_Linux_Cryptominer_Generic_D7Bd0E5D : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "d7bd0e5d-3528-4648-aaa5-6cf44d22c0d5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "afcfd67af99e437f553029ccf97b91ed0ca891f9bcc01c148c2b38c75482d671"
		logic_hash = "1f87721fdfe58d029c0696bc99385a0052c771bc48b2c9ce01b72c3e42359654"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fbc06c7603aa436df807ad3f77d5ba783c4d33f61b06a69e8641741068f3a543"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CF 99 67 D8 37 AA 24 80 F2 F3 47 6A A5 5E 88 50 F1 28 61 18 }

	condition:
		all of them
}