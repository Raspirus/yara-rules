rule ELASTIC_Linux_Trojan_Patpooty_E2E0Dff1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Patpooty (Linux.Trojan.Patpooty)"
		author = "Elastic Security"
		id = "e2e0dff1-bb01-437e-b138-7da3954dc473"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Patpooty.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d38b9e76cbc863f69b29fc47262ceafd26ac476b0ae6283d3fa50985f93bedf3"
		logic_hash = "ec7d12296383ca0ed20e3221fb96b9dbdaf6cc7f07f5c8383e43489a9fd6fcfe"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "275ff92c5de2d2183ea8870b7353d24f026f358dc7d30d1a35d508a158787719"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F0 8B 45 E4 8B 34 88 8D 7E 01 FC 31 C0 83 C9 FF F2 AE F7 D1 83 }

	condition:
		all of them
}