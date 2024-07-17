rule ELASTIC_Linux_Trojan_Sfloost_69A5343A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sfloost (Linux.Trojan.Sfloost)"
		author = "Elastic Security"
		id = "69a5343a-4885-4d88-9eaf-ddfcc95e1f39"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sfloost.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c0cd73db5165671c7bbd9493c34d693d25b845a9a21706081e1bf44bf0312ef9"
		logic_hash = "bd3cd33d02c7ca1d3a0364e5e3e2f968f32da8f087f744232f3cb786da6c7875"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c19368bf04e4b67537a8573b5beba56bab8bcfdf870640ef5bd46d40735ee539"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 83 C8 50 88 43 0C 0F B6 45 F0 66 C7 43 10 00 00 66 C7 43 12 }

	condition:
		all of them
}