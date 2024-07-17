rule ELASTIC_Linux_Trojan_Kaiji_Dcf6565E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Kaiji (Linux.Trojan.Kaiji)"
		author = "Elastic Security"
		id = "dcf6565e-8287-4d78-b103-53cfab192025"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Kaiji.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "49f3086105bdc160248e66334db00ce37cdc9167a98faac98800b2c97515b6e7"
		logic_hash = "2bc943e100548e9aacd97930b3230353be760c8a292dbbbd1d0b5646f647c4fe"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "381d6b8f6a95800fe0d20039f991ce82317f60aef100487f3786e6c1e63376e1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 69 D2 9B 00 00 00 48 C1 EA 20 83 C2 64 48 8B 9C 24 B8 00 }

	condition:
		all of them
}