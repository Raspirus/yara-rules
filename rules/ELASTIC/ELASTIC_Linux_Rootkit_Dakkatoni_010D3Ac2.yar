rule ELASTIC_Linux_Rootkit_Dakkatoni_010D3Ac2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Rootkit Dakkatoni (Linux.Rootkit.Dakkatoni)"
		author = "Elastic Security"
		id = "010d3ac2-0bb2-4966-bf5f-fd040ba07311"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Rootkit_Dakkatoni.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "38b2d033eb5ce87faa4faa7fcac943d9373e432e0d45e741a0c01d714ee9d4d3"
		logic_hash = "51119321f29aed695e09da22d3234eae96db93e8029d4525d018e56c7131f7b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2c7935079dc971d2b8a64c512ad677e946ff45f7f1d1b62c3ca011ebde82f13b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 C8 C1 E0 0D 31 C1 89 CE 83 E6 03 83 C6 05 89 C8 31 D2 C1 }

	condition:
		all of them
}