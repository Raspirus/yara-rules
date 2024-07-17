rule ELASTIC_Linux_Trojan_Generic_181054Af : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "181054af-dc05-4981-8a57-ea17ffd6241f"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L261-L279"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e677f1eed0dbb4c680549e0bf86d92b0a28a85c6d571417baaba0d0719da5f93"
		logic_hash = "e92807b603dd33fe7a083985644a213913a77e81c068623fdac7931148207b91"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8ef033ac0fccd10cdf2e66446461b7c8b29574e5869440a1972dbe4bb5fbed89"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6D 6F 64 00 73 65 74 75 74 78 65 6E 74 00 67 6D 74 69 6D 65 00 }

	condition:
		all of them
}