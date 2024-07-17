rule ELASTIC_Linux_Trojan_Tsunami_30C039E2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "30c039e2-1c51-4309-9165-e3f2ce79cd6e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b494ca3b7bae2ab9a5197b81e928baae5b8eac77dfdc7fe1223fee8f27024772"
		logic_hash = "a9dbfede68a3209b403aa40dbc5b69326c3e1c14259ed6bc6351f0f9412cfce2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4c97fed719ecfc68e7d67268f19aff545447b4447a69814470fe676d4178c0ed"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 E0 0F B6 00 84 C0 74 1F 48 8B 45 E0 48 8D 50 01 48 8B 45 E8 48 83 }

	condition:
		all of them
}