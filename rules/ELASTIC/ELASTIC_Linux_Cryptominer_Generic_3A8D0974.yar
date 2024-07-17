rule ELASTIC_Linux_Cryptominer_Generic_3A8D0974 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "3a8d0974-384e-4d62-9aa8-0bd8f7d50206"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "193fe9ea690759f8e155458ef8f8e9efe9efc8c22ec8073bbb760e4f96b5aef7"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L581-L599"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "7039d461d8339d635a543fae2c6dbea284ce1b727d6585b69d8d621c603f37ac"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "60cb81033461e73fcb0fb8cafd228e2c9478c132f49e115c5e55d5579500caa2"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 07 41 89 34 06 48 83 C0 04 48 83 F8 20 75 EF 8B 42 D4 66 0F }

	condition:
		all of them
}