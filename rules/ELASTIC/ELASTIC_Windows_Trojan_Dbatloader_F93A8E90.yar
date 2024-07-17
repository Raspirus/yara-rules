rule ELASTIC_Windows_Trojan_Dbatloader_F93A8E90 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Dbatloader (Windows.Trojan.DBatLoader)"
		author = "Elastic Security"
		id = "f93a8e90-10ac-44de-ac3b-c0e976628e98"
		date = "2022-03-11"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DBatLoader.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f72d7e445702bbf6b762ebb19d521452b9c76953d93b4d691e0e3e508790256e"
		logic_hash = "6fe91d91bb383c66a6dc623b02817411a39b88030142517f4048c5c25fbb4ac5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "81b87663fbad9854430e5c4dcade464a15b995e645f9993a3e234593ee4df901"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { FF 00 74 17 8B 45 E8 0F B6 7C 18 FF 66 03 7D EC 66 0F AF 7D F4 66 03 }

	condition:
		all of them
}