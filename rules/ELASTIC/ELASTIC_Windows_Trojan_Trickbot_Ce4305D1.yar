rule ELASTIC_Windows_Trojan_Trickbot_Ce4305D1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "ce4305d1-8a6f-4797-afaf-57e88f3d38e6"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L41-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "c547114475383e5d84f6b8cb72585ddd5778ae3afa491deddeef8a5ec56be1b5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ae606e758b02ccf2a9a313aebb10773961121f79a94c447e745289ee045cf4ee"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { F9 8B 45 F4 89 5D E4 85 D2 74 39 83 C0 02 03 C6 89 45 F4 8B }

	condition:
		all of them
}