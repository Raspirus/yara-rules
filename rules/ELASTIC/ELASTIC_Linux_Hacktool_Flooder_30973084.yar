
rule ELASTIC_Linux_Hacktool_Flooder_30973084 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "30973084-60d2-494d-a3c6-2a015a9459a0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L260-L278"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a22ffa748bcaaed801f48f38b26a9cfdd5e62183a9f6f31c8a1d4a8443bf62a4"
		logic_hash = "d965a032c0fb6020c6187aa3117f7251dd8c9287c45453e3d5ae2ac62b3067bb"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "44fc236199ccf53107f1a617ac872f51d58a99ec242fe97b913e55b3ec9638e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4C 69 73 74 20 49 6D 70 6F 72 74 20 46 6F 72 20 53 6F 75 72 63 }

	condition:
		all of them
}