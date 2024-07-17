rule ELASTIC_Linux_Trojan_Mirai_B9A9D04B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "b9a9d04b-a997-46c4-b893-e89a3813efd3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L911-L928"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "61575576be4c1991bc381965a40e5d9d751bba2680a42907b0148651716419fc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "874249d8ad391be97466c0259ae020cc0564788a6770bb0f07dd0653721f48b1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = "nexuszetaisacrackaddict"

	condition:
		all of them
}