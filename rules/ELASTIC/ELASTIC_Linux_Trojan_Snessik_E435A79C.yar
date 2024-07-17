
rule ELASTIC_Linux_Trojan_Snessik_E435A79C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Snessik (Linux.Trojan.Snessik)"
		author = "Elastic Security"
		id = "e435a79c-4b8e-42de-8d78-51b684eba178"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Snessik.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e24749b07f824a4839b462ec4e086a4064b29069e7224c24564e2ad7028d5d60"
		logic_hash = "4850530a0566844447f56f4e5cb43c5982b1dcb784bb1aef3e377525b8651ed3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bd9f81d03812e49323b86b2ea59bf5f08021d0b43f7629eb4d59e75eccb7dcf1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C6 75 38 31 C0 48 8B 5C 24 68 48 8B 6C 24 70 4C 8B 64 24 78 4C 8B AC 24 80 00 }

	condition:
		all of them
}