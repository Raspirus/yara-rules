
rule ELASTIC_Linux_Trojan_Sshdoor_7C36D3Dd : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sshdoor (Linux.Trojan.Sshdoor)"
		author = "Elastic Security"
		id = "7c36d3dd-734f-4485-85c5-906c5ecade77"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sshdoor.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "def4de838d58c70f9f0ae026cdad3bf09b711a55af97ed20804fa1e34e7b59e9"
		logic_hash = "c1b61fce7593a44e47043fac8a6356f9aa9e74b66db005400684a5a79b69a5cd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a644708905c97c784f394ebbd0020dd3b20b52b4f536c844ca860dabea36ceb7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 20 48 89 E7 C1 EE 03 83 E6 01 FF D3 8B 54 24 20 31 C0 BE 20 00 }

	condition:
		all of them
}