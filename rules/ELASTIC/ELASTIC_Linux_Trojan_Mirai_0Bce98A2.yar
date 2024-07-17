
rule ELASTIC_Linux_Trojan_Mirai_0Bce98A2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "0bce98a2-113e-41e1-95c9-9e1852b26142"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1008-L1026"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1b20df8df7f84ad29d81ccbe276f49a6488c2214077b13da858656c027531c80"
		logic_hash = "04d10ef03c178fb101d3c6b6d3b36f0aa04149b9b35a33c3d10d17af1fc07625"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "993d0d2e24152d0fb72cc5d5add395bed26671c3935f73386341398b91cb0e6e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4B 52 41 00 46 47 44 43 57 4E 56 00 48 57 43 4C 56 47 41 4A }

	condition:
		all of them
}