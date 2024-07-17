
rule ELASTIC_Linux_Trojan_Sqlexp_1Aa5001E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sqlexp (Linux.Trojan.Sqlexp)"
		author = "Elastic Security"
		id = "1aa5001e-0609-4830-9c6f-675985fa50cf"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sqlexp.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "714a520fc69c54bcd422e75f4c3b71ce636cfae7fcec3c5c413d1294747d2dd6"
		logic_hash = "48c7331c80aa7d918f46d282c6f38b8e780f9b5222cf9304bf1a8bb39cc129ab"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "afce33f5bf064afcbd8b1639755733c99171074457272bf08f0c948d67427808"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E3 52 53 89 E1 B0 0B CD 80 00 00 ?? 00 }

	condition:
		all of them
}