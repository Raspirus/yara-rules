
rule ELASTIC_Linux_Trojan_Gafgyt_Eb96Cc26 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "eb96cc26-e6d6-4388-a5da-2501e6e2ea32"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L40-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "440318179ba2419cfa34ea199b49ee6bdecd076883d26329bbca6dca9d39c500"
		logic_hash = "3d8740a6cca4856a73ea745877a3eb39cbf3ad4ca612daabd197f551116efa04"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "73967a3499d5dce61735aa2d352c1db48bb1d965b2934bb924209d729b5eb162"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 49 6E 66 6F 3A 20 0A 00 5E 6A 02 5F 6A 01 58 0F 05 6A 7F 5F }

	condition:
		all of them
}