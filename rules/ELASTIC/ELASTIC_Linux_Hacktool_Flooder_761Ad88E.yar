
rule ELASTIC_Linux_Hacktool_Flooder_761Ad88E : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "761ad88e-1667-4253-81f6-52c92e0ccd68"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
		logic_hash = "2b0c64da713e2f8ff671cbe086638810bc02a983d42851e78c68a57bde9f023c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "14e701abdef422dcde869a2278ec6e1fb7889dcd9681a224b29a00bcb365e391"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 2E 31 36 38 2E 33 2E 31 30 30 00 43 6F 75 6C 64 20 6E 6F 74 }

	condition:
		all of them
}