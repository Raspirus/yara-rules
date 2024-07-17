rule ELASTIC_Linux_Trojan_Mechbot_F2E1C5Aa : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mechbot (Linux.Trojan.Mechbot)"
		author = "Elastic Security"
		id = "f2e1c5aa-3318-4665-bee4-34a4afcf60bd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mechbot.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5f8e80e6877ff2de09a12135ee1fc17bee8eb6d811a65495bcbcddf14ecb44a3"
		logic_hash = "2ba9ece1ab2360702a59a737a20b6dbd8fca276b543477f9290ab80c6f51e2f1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4b663b0756f2ae9b43eae29cd0225ad75517ef345982e8fdafa61f3c3db2d9f5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 52 56 45 52 00 42 41 4E 4C 49 53 54 00 42 4F 4F 54 00 42 }

	condition:
		all of them
}