rule ELASTIC_Linux_Hacktool_Flooder_A2795A4C : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "a2795a4c-16c0-4237-a014-3570d1edb287"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L180-L198"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
		logic_hash = "18e15b8a417f9ff2fd9277a01eb3224c761807ce9541ece568f4525ae66eb81f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7c8bf248b159f3a140f10cd40d182fa84f334555b92306e6f44e746711b184cc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 8B 45 D8 66 89 50 04 48 8B 45 D8 0F B7 40 02 66 D1 E8 0F }

	condition:
		all of them
}