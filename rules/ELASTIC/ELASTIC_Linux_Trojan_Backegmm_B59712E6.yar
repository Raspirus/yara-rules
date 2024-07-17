rule ELASTIC_Linux_Trojan_Backegmm_B59712E6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Backegmm (Linux.Trojan.Backegmm)"
		author = "Elastic Security"
		id = "b59712e6-d14d-4a57-a3d6-2dc323bf840d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Backegmm.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d6c8e15cb65102b442b7ee42186c58fa69cd0cb68f4fd47eb5ad23763371e0be"
		logic_hash = "a2e6016bfd8475880c28c89b5f5beeef1335de9529d44bbe7c5aaa352aab9a29"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "61b2f0c7cb98439b05776edeaf06b114d364119ebe733d924158792110c5e21c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 69 73 74 65 6E 00 66 6F 72 6B 00 73 70 72 69 6E 74 66 00 68 }

	condition:
		all of them
}