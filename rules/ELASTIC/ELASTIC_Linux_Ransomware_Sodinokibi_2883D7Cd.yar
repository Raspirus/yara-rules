
rule ELASTIC_Linux_Ransomware_Sodinokibi_2883D7Cd : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Sodinokibi (Linux.Ransomware.Sodinokibi)"
		author = "Elastic Security"
		id = "2883d7cd-fd3b-47a5-9283-a40335172c62"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Sodinokibi.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a322b230a3451fd11dcfe72af4da1df07183d6aaf1ab9e062f0e6b14cf6d23cd"
		logic_hash = "97d6b1b641c4b5b596b67a809e8e70bb0bccb9219282cd6c41bc905e2ea44c84"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d6570a8e9358cef95388a72b2e7f747ee5092620c4f92a4b4e6c1bb277e1cb36"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 85 08 FF FF FF 48 01 85 28 FF FF FF 48 8B 85 08 FF FF FF 48 29 85 20 FF }

	condition:
		all of them
}