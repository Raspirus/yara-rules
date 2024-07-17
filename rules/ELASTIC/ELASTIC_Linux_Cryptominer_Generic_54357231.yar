
rule ELASTIC_Linux_Cryptominer_Generic_54357231 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "54357231-23d8-44f5-94d7-71da02a8ba38"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L801-L819"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
		logic_hash = "a895c9fd124d6bd55748093c3ef54606e5692285260aa21bd70dca02126239d2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8bbba49c863bc3d53903b1a204851dc656f3e3d68d3c8d5a975ed2dc9e797e13"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 73 F2 06 C5 F9 EB C2 C4 E3 79 16 E0 02 C4 E3 79 16 E2 03 C5 F9 70 }

	condition:
		all of them
}