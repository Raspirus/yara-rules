
rule ELASTIC_Linux_Backdoor_Bash_E427876D : FILE MEMORY
{
	meta:
		description = "Detects Linux Backdoor Bash (Linux.Backdoor.Bash)"
		author = "Elastic Security"
		id = "e427876d-c7c5-447a-ad6d-5cbc12d9dacf"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Backdoor_Bash.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
		logic_hash = "fdd066b746416730419787d21eb53fa2ba997679a237d9db3a2e1365d43df892"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "6cc13bb2591d896affc58f4a22b3463a72f6c9d896594fe1714b825e064b0956"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 67 65 44 6F 6B 4B 47 6C 6B 49 43 31 31 4B 54 6F 67 4C 32 56 }

	condition:
		all of them
}