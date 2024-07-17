rule ELASTIC_Linux_Backdoor_Generic_Babf9101 : FILE MEMORY
{
	meta:
		description = "Detects Linux Backdoor Generic (Linux.Backdoor.Generic)"
		author = "Elastic Security"
		id = "babf9101-1e6e-4268-a530-e99e2c905b0d"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Backdoor_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9ea73d2c2a5f480ae343846e2b6dd791937577cb2b3d8358f5b6ede8f3696b86"
		logic_hash = "40084f3bed66c1d4a1cd2ffca99fd6789c8ed2db04031e4d4a4926b41d622355"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a578b052910962523f26f14f0d0494481fe0777c01d9f6816c7ab53083a47adc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C4 10 89 45 F4 83 7D F4 00 79 1F 83 EC 0C 68 22 }

	condition:
		all of them
}