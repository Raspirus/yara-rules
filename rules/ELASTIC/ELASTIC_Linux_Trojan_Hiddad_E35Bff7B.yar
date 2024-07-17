rule ELASTIC_Linux_Trojan_Hiddad_E35Bff7B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Hiddad (Linux.Trojan.Hiddad)"
		author = "Elastic Security"
		id = "e35bff7b-1a93-4cfd-a4b6-1e994c0afa98"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Hiddad.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "22a418e660b5a7a2e0cc1c1f3fe1d150831d75c4fedeed9817a221194522efcf"
		logic_hash = "3881222807585dc933cb61473751d13297fa7eb085a50d435d3b680354a35ee9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0ed46ca8a8bd567acf59d8a15a9597d7087975e608f42af57d36c31e777bb816"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 3C 14 48 63 CF 89 FE 48 69 C9 81 80 80 80 C1 FE 1F 48 C1 E9 20 }

	condition:
		all of them
}