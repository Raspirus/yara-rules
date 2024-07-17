rule ELASTIC_Linux_Cryptominer_Flystudio_579A3A4D : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Flystudio (Linux.Cryptominer.Flystudio)"
		author = "Elastic Security"
		id = "579a3a4d-ddb0-4f73-9224-16fba973d624"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Flystudio.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "84afc47554cf42e76ef8d28f2d29c28f3d35c2876cec2fb1581b0ac7cfe719dd"
		logic_hash = "6579630a4fb6cf5bc8ccb2e4f93f5d549baa6ea9b742b2ee83a52f07352c4741"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "148b27046f72a7645ebced9f76424ffd7b368347311b04c9357d5d4ea8d373fb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EF C1 66 0F 72 F1 05 66 0F EF C2 66 0F EF C1 66 0F 6F CD 66 0F }

	condition:
		all of them
}