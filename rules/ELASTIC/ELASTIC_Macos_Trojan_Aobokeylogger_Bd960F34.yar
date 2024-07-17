
rule ELASTIC_Macos_Trojan_Aobokeylogger_Bd960F34 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Aobokeylogger (MacOS.Trojan.Aobokeylogger)"
		author = "Elastic Security"
		id = "bd960f34-1932-41be-ac0a-f45ada22c560"
		date = "2021-10-18"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Aobokeylogger.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2b50146c20621741642d039f1e3218ff68e5dbfde8bb9edaa0a560ca890f0970"
		logic_hash = "f89fbf1d6bf041de0ce32f7920818c34ce0eeb6779bb7fac6f223bbea1c6f6fa"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "ae26a03d1973669cbeaabade8f3fd09ef2842b9617fa38e7b66dc4726b992a81"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 20 74 68 61 6E 20 32 30 30 20 6B 65 79 73 74 72 6F 6B 65 73 20 }

	condition:
		all of them
}