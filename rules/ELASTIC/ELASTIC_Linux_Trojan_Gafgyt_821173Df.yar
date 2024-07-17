rule ELASTIC_Linux_Trojan_Gafgyt_821173Df : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "821173df-6835-41e1-a662-a432abf23431"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L336-L354"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "de7d1aff222c7d474e1a42b2368885ef16317e8da1ca3a63009bf06376026163"
		logic_hash = "1c6c7666983c43176aa1a9628fb4352f8f11729e02dda13669ca2e62aed5f4ee"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c311789e1370227f7be1d87da0c370a905b7f5b4c55cdee0f0474060cc0fc5e4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D0 48 FF C8 48 03 45 F8 48 FF C8 C6 00 00 48 8B 45 F8 48 C7 C1 FF FF }

	condition:
		all of them
}