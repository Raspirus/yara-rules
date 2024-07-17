
rule ELASTIC_Linux_Hacktool_Flooder_9417F77B : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "9417f77b-190b-4834-b57a-08a7cbfac884"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "60ff13e27dad5e6eadb04011aa653a15e1a07200b6630fdd0d0d72a9ba797d68"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L620-L638"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "470b7e44cd875b1f6abcfa5e4d33d2808a65630dc914b38643c9efb14db5f1ff"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d321ea7aeb293f8f50236bddeee99802225b70e8695bb3527a89beea51e3ffb3"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F B7 45 F6 0F B7 C0 48 01 C3 48 89 DA 48 C1 FA 10 0F B7 C3 48 8D }

	condition:
		all of them
}