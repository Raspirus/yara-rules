
rule ELASTIC_Linux_Trojan_Sysrv_85097F24 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sysrv (Linux.Trojan.Sysrv)"
		author = "Elastic Security"
		id = "85097f24-2e2e-41e4-8769-dca7451649cc"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "17fbc8e10dea69b29093fcf2aa018be4d58fe5462c5a0363a0adde60f448fb26"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sysrv.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "96bee8b9b0e9c2afd684582301f9e110fd08fcabaea798bfb6259a4216f69be1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1cad651c92a163238f8d60d2e3670f229b4aafd6509892b9dcefe014b39c6f7d"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 32 26 02 0F 80 0C 0A FF 0B 02 02 22 04 2B 02 16 02 1C 01 0C 09 }

	condition:
		all of them
}