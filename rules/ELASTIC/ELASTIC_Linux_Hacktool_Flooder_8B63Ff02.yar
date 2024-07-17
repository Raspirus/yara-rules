rule ELASTIC_Linux_Hacktool_Flooder_8B63Ff02 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "8b63ff02-be86-4c63-8f7b-4c70fbd8a83a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L240-L258"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
		logic_hash = "3b68353c8eeb21a3eba7a02ae76b66b4f094ec52d5309582544d247cc6548da3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "af7a4df7e707c1b70fb2b29efe2492e6f77cdde5e8d1e6bfdf141acabc8759eb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { DC 02 83 7D DC 01 0F 9F C0 84 C0 75 DF 83 7D DC 01 75 1D 66 C7 45 F6 }

	condition:
		all of them
}