rule ELASTIC_Windows_Trojan_Trickbot_Cb95Dc06 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "cb95dc06-6383-4487-bf10-7fd68d61e37a"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L193-L210"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "563b2311d37ace2d09601a70325352db3fcbf135e7ce518965f5410081b5d626"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0d28f570db007a1b91fe48aba18be7541531cceb7f11a6a4471e92abd55b3b90"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 08 5F 5E 33 C0 5B 5D C3 8B 55 14 89 02 8B 45 18 5F 89 30 B9 01 00 }

	condition:
		all of them
}