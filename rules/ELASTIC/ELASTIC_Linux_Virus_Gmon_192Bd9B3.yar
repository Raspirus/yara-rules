
rule ELASTIC_Linux_Virus_Gmon_192Bd9B3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Virus Gmon (Linux.Virus.Gmon)"
		author = "Elastic Security"
		id = "192bd9b3-230a-4f07-b4f9-06213a6b6f47"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Virus_Gmon.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d0fe377664aa0bc0d1fd3a307650f211dd3ef2e2f04597abee465e836e6a6f32"
		logic_hash = "3df275349d14a845c73087375f96e0c9a069ff685beb89249590ef9448e50373"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "532055052554ed9a38b16f764d3fbae0efd333f5b2254b9a1e3f6d656d77f1e4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E5 56 53 8B 75 08 8B 5D 0C 8B 4D 10 31 D2 39 CA 7D 11 8A 04 1A 38 }

	condition:
		all of them
}