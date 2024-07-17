
rule ELASTIC_Linux_Trojan_Gafgyt_71E487Ea : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "71e487ea-a592-469c-a03e-0c64d2549e74"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L614-L632"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b8d044f2de21d20c7e4b43a2baf5d8cdb97fba95c3b99816848c0f214515295b"
		logic_hash = "3de9e0e3334e9e6e5906886f95ff8ce3596f85772dc25021fb0ee148281cf81c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8df69968ddfec5821500949015192b6cdbc188c74f785a272effd7bc9707f661"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E0 8B 45 D8 8B 04 D0 8D 50 01 83 EC 0C 8D 85 40 FF FF FF 50 }

	condition:
		all of them
}