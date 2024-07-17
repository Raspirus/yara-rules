rule ELASTIC_Linux_Trojan_Ganiw_99349371 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ganiw (Linux.Trojan.Ganiw)"
		author = "Elastic Security"
		id = "99349371-644e-4954-9b7d-f2f579922565"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ganiw.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e8dbb246fdd1a50226a36c407ac90eb44b0cf5e92bf0b92c89218f474f9c2afb"
		logic_hash = "26160e855c63fc0b73e415de2fe058f2005df1ec5544d21865d022c5474df30c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6b0cbea419915567c2ecd84bfcb2c7f7301435ee953f16c6dcba826802637551"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 66 89 43 02 8B 5D FC C9 C3 55 89 E5 53 83 EC 04 8B 45 14 8B }

	condition:
		all of them
}