
rule ELASTIC_Linux_Cryptominer_Xmrig_271121Fb : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "271121fb-47cf-47a7-9e90-8565d4694c9e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "19aeafb63430b5ac98e93dfd6469c20b9c1145e6b5b86202553bd7bd9e118842"
		logic_hash = "f43b1527ad4bbd07023126def89c1af47698cc832f71f4a1381ed0d621d79ed5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e0968731b0e006f3db92762822e4a3509d800e8f270b1c38303814fd672377a2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 18 41 C1 E4 10 C1 E1 08 41 C1 EA 10 44 89 CB 41 C1 E9 18 C1 }

	condition:
		all of them
}