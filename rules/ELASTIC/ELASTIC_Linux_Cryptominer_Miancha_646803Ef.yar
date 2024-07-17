
rule ELASTIC_Linux_Cryptominer_Miancha_646803Ef : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Miancha (Linux.Cryptominer.Miancha)"
		author = "Elastic Security"
		id = "646803ef-e8a5-46e2-94a5-dcc6cb41cead"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Miancha.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4c7761c9376ed065887dc6ce852491641419eb2d1f393c37ed0a5cb29bd108d4"
		logic_hash = "8fd386c0e7037565e8ab206642cc8c11f05ca727b365b94ffdd991f4bed95556"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b22f87b60c19855c3ac622bc557655915441f5e12c7d7c27c51c05e12c743ee5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6F DC 66 0F 73 FB 04 66 0F EF C1 66 0F 6F D3 66 0F EF C7 66 0F 6F }

	condition:
		all of them
}