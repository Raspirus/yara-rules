
rule ELASTIC_Linux_Trojan_Rbot_96625C8C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rbot (Linux.Trojan.Rbot)"
		author = "Elastic Security"
		id = "96625c8c-897c-4bf0-97e7-0dc04595cb94"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rbot.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a052cfad3034d851c6fad62cc8f9c65bceedc73f3e6a37c9befe52720fd0890e"
		logic_hash = "5a9671e10e7b9b58ecf9fab231de18b4b6039c9d351b145fae1705297acda95e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5dfabf693c87742ffa212573dded84a2c341628b79c7d11c16be493957c71a69"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 28 8B 45 3C 8B 54 05 78 01 EA 8B 4A 18 8B 5A 20 01 EB E3 38 49 8B }

	condition:
		all of them
}