rule ELASTIC_Linux_Trojan_Mirai_Ab804Bb7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "ab804bb7-57ab-48db-85cc-a6d88de0c84a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1482-L1500"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8f0cc764729498b4cb9c5446f1a84cde54e828e913dc78faf537004a7df21b20"
		logic_hash = "cef2ffafe152332502fb0d72d014c81b90dc9ad4f4491f1b2f2f9c1f73cc7958"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b9716aa7be1b0e4c966a25a40521114e33c21c7ec3c4468afc1bf8378dd11932"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4A 75 05 0F BE 11 01 D0 89 C2 0F B7 C0 C1 FA 10 01 C2 89 D0 C1 }

	condition:
		all of them
}