
rule ELASTIC_Linux_Cryptominer_Xmrig_Dbcc9D87 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "dbcc9d87-5064-446d-9581-b14cf183ec3f"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L218-L236"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "da9b8fb5c26e81fb3aed3b0bc95d855339fced303aae2af281daf0f1a873e585"
		logic_hash = "b7fa60e32cb53484d8b76b13066eda1f2275ee2660ac2dc02b0078b921998e79"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ebb6d184d7470437aace81d55ada5083e55c0de67e566b052245665aeda96d69"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 78 72 47 47 58 34 53 58 5F 34 74 43 41 66 30 5A 57 73 00 64 48 8B 0C 25 F8 FF }

	condition:
		all of them
}