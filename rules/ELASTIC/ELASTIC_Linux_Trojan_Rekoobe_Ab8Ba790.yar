rule ELASTIC_Linux_Trojan_Rekoobe_Ab8Ba790 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rekoobe (Linux.Trojan.Rekoobe)"
		author = "Elastic Security"
		id = "ab8ba790-d2dd-4756-af5c-6f78ba10c92d"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rekoobe.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2aee0c74d9642ffab1f313179c26400acf60d7cbd2188bade28534d403f468d4"
		logic_hash = "2a7a71712ad3f756a2dc53ec80bd9fb625f7c679fd9566945ebfeb392b9874a9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "decdd02a583562380eda405dcb892d38558eb868743ebc44be592f4ae95b5971"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { DB F9 66 0F 71 D1 08 66 0F 67 DD 66 0F DB E3 66 0F 71 D3 08 66 0F }

	condition:
		all of them
}