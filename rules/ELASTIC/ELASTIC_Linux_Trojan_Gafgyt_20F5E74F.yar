rule ELASTIC_Linux_Trojan_Gafgyt_20F5E74F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "20f5e74f-9f94-431b-877c-9b0d78a1d4eb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L812-L830"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9084b00f9bb71524987dc000fb2bc6f38e722e2be2832589ca4bb1671e852f5b"
		logic_hash = "067f1c15961c1ddceecb490b338db9f5b8501d89b38e870edfa628d21527dc1c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "070fe0d678612b4ec8447a07ead0990a0abd908ce714388720e7fd7055bf1175"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D8 8B 45 D0 8B 04 D0 8D 50 01 83 EC 0C 8D 85 38 FF FF FF 50 8D 85 40 FF }

	condition:
		all of them
}