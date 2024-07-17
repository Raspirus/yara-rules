
rule ELASTIC_Linux_Trojan_Mirai_A2D2E15A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "a2d2e15a-a2eb-43c6-a43d-094ee9739749"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L318-L336"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "567c3ce9bbbda760be81c286bfb2252418f551a64ba1189f6c0ec8ec059cee49"
		logic_hash = "c76fe953c4a70110346a020f2b27c7e79f4ad8a24fd92ac26e5ddd1fed068f65"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0e57d17f5c0cd876248a32d4c9cbe69b5103899af36e72e4ec3119fa48e68de2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 42 F0 41 83 F8 01 76 5F 44 0F B7 41 10 4C 01 C0 44 8D 42 EE 41 83 }

	condition:
		all of them
}