rule ELASTIC_Linux_Trojan_Gafgyt_0Cd591Cd : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "0cd591cd-c348-4c3a-a895-2063cf892cda"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L932-L949"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "4300bdd173dfb33ca34c0f2fe4fa6ee071e99d5db201262e914721aad0ad433b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "96c4ff70729ddb981adafd8c8277649a88a87e380d2f321dff53f0741675fb1b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4E F8 48 8D 4E D8 49 8D 42 E0 48 83 C7 03 EB 6B 4C 8B 46 F8 48 8D }

	condition:
		all of them
}