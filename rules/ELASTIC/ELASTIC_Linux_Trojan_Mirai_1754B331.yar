
rule ELASTIC_Linux_Trojan_Mirai_1754B331 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "1754b331-5704-43c1-91be-89c7a0dd29a4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1442-L1460"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0d89fc59d0de2584af0e4614a1561d1d343faa766edfef27d1ea96790ac7014b"
		logic_hash = "fde04b0e31a00326f9d011198995999ff9b15628f5ff4139ec7dec19ac0c59c9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "35db945d116a4c9264af44a9947a5e831ea655044728dc78770085c7959a678e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CF 07 66 5F 10 F0 EB 0C 42 0B 2F 0B 0B 43 C1 42 E4 C2 7C 85 }

	condition:
		all of them
}