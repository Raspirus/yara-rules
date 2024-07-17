rule ELASTIC_Linux_Virus_Gmon_E544D891 : FILE MEMORY
{
	meta:
		description = "Detects Linux Virus Gmon (Linux.Virus.Gmon)"
		author = "Elastic Security"
		id = "e544d891-3f6d-4da2-be86-e4ab58c66465"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Virus_Gmon.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d0fe377664aa0bc0d1fd3a307650f211dd3ef2e2f04597abee465e836e6a6f32"
		logic_hash = "6dcfd51aaa79d7bac0100d9c891aa4275b8e1f7614cda46a5da4c738d376c729"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "269f0777f846f9fc8fe56ea7436bddb155cde8c9a4bf9070f46db0081caef718"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E5 53 51 52 8B 44 24 14 8B 5C 24 18 8B 4C 24 1C 8B 54 24 20 }

	condition:
		all of them
}