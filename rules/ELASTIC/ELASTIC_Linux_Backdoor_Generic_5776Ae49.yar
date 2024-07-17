
rule ELASTIC_Linux_Backdoor_Generic_5776Ae49 : FILE MEMORY
{
	meta:
		description = "Detects Linux Backdoor Generic (Linux.Backdoor.Generic)"
		author = "Elastic Security"
		id = "5776ae49-64e9-46a0-a0bb-b0226eb9a8bd"
		date = "2021-04-06"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Backdoor_Generic.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e247a5decb5184fd5dee0d209018e402c053f4a950dae23be59b71c082eb910c"
		logic_hash = "b606f12c47182d80e07f8715639c3cc73753274bd8833cb9f6380879356a2b12"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2d36fbe1820805c8fd41b2b34a2a2b950fc003ae4f177042dc0d2568925c5b76"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 18 C1 E8 08 88 47 12 8B 46 18 88 47 13 83 C4 1C 5B 5E 5F 5D }

	condition:
		all of them
}