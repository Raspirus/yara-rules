rule ELASTIC_Linux_Trojan_Morpes_D2Ae1Edf : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Morpes (Linux.Trojan.Morpes)"
		author = "Elastic Security"
		id = "d2ae1edf-7dd3-4506-96e0-039c8f00d688"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Morpes.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "14c4c297388afe4be47be091146aea6c6230880e9ea43759ef29fc1471c4b86b"
		logic_hash = "27eb8b4d0f91477c2ac26a5e25bfc52903faf5501300ec40773d3fc6797c3218"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a4cedb0ef6c9c5121ee63c0c8f6bb8072f62b5866c916c7000d94999cd61b9b5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 64 B0 05 00 00 B0 05 00 00 B0 05 00 00 3C 00 00 00 3C 00 00 00 }

	condition:
		all of them
}