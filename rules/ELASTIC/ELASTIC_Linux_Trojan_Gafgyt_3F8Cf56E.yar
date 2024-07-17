rule ELASTIC_Linux_Trojan_Gafgyt_3F8Cf56E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "3f8cf56e-a8cb-4c03-8829-f1daa3dc64a8"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "1878f0783085cc6beb2b81cfda304ec983374264ce54b6b98a51c09aea9f750d"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1287-L1305"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "b2cf8b1913a88e6a6346f0ac8cd2e7c33b41d44bf60ff7327ae40a2d54748bd9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "77306f0610515434371f70f2b42c895cdc5bbae2ef6919cf835b3cfe2e4e4976"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 2F DA E8 E9 CC E4 F4 39 55 E2 9E 33 0E C0 F0 FB 26 93 31 }

	condition:
		all of them
}