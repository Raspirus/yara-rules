rule ELASTIC_Linux_Virus_Thebe_1Eb5985A : FILE MEMORY
{
	meta:
		description = "Detects Linux Virus Thebe (Linux.Virus.Thebe)"
		author = "Elastic Security"
		id = "1eb5985a-2b35-434f-81d9-f502dff25397"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Virus_Thebe.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "30af289be070f4e0f8761f04fb44193a037ec1aab9cc029343a1a1f2a8d67670"
		logic_hash = "7d4bc4b1615048dec1f1fac599afa667e06ccb369bb1242b25887e0ce2a5066a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5cf9aa9a31c36028025d5038c98d56aef32c9e8952aa5cd4152fbd811231769e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 42 31 C9 31 DB 31 F6 B0 1A CD 80 85 C0 0F 85 83 }

	condition:
		all of them
}