
rule ELASTIC_Linux_Hacktool_Portscan_6C6000C2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Portscan (Linux.Hacktool.Portscan)"
		author = "Elastic Security"
		id = "6c6000c2-7e9a-457c-a745-00a3ac83a4bc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Portscan.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8877009fc8ee27ba3b35a7680b80d21c84ee7296bcabe1de51aeeafcc8978da7"
		logic_hash = "0cae81cbc0fdf48b4e7ac09865f05e2ad93d79b7a6f1af76a632727127ab050f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3c893aebe688d70aebcb15fdc0d2780d2ec0589084c915ff71519ec29e5017f1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 30 B9 0E 00 00 00 4C 89 D7 F3 A6 0F 97 C2 80 DA 00 84 D2 45 0F }

	condition:
		all of them
}