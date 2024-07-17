
rule ELASTIC_Linux_Trojan_Tsunami_32C0B950 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "32c0b950-0636-42bb-bc67-1b727985625f"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L400-L418"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "214c1caf20ceae579476d3bf97f489484df4c5f1c0c44d37ff9b9066072cd83c"
		logic_hash = "db077e5916327ca78fcc9dc35f64e5c497dbbe60c4a0c1eb7abb49c555765681"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e438287517c3492fa87115a3aa5402fd05f9745b7aed8e251fb3ed9d653984bb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 05 20 BC F8 41 B8 20 07 09 20 35 15 11 03 20 85 }

	condition:
		all of them
}