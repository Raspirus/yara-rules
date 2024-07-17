
rule ELASTIC_Linux_Hacktool_Flooder_1Cfa95Dd : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "1cfa95dd-e768-4071-9038-389c580741f9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L280-L298"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
		logic_hash = "f73a96cc379c8dc060bfe5668ef7e47c5bcd037b3f41c300ef20c2f2f653cb00"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6ec21acb987464613830b3bbe1e2396093d269dae138c68fe77f35d88796001e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 7D EC 00 7E 0F 48 8B 45 F0 0F B6 00 0F B6 C0 48 01 C3 EB 10 }

	condition:
		all of them
}