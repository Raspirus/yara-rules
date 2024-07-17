rule ELASTIC_Linux_Trojan_Mirai_76Bbc4Ca : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "76bbc4ca-e6da-40f7-8ba6-139ec8393f35"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "1a9ff86a66d417678c387102932a71fd879972173901c04f3462de0e519c3b51"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1742-L1760"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "855b7938b92b5645fcefd2ec1e2ccb71269654816f362282ccbf9aef1c01c8a0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4206c56b538eb1dd97e8ba58c5bab6e21ad22a0f8c11a72f82493c619d22d9b7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 40 2D E9 00 40 A0 E1 28 20 84 E2 0C 00 92 E8 3B F1 FF EB }

	condition:
		all of them
}