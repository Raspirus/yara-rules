rule ELASTIC_Linux_Trojan_Gafgyt_33801844 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "33801844-50b1-4968-a1b7-d106f16519ee"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1128-L1146"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2ceff60e88c30c02c1c7b12a224aba1895669aad7316a40b575579275b3edbb3"
		logic_hash = "20b8ebce14776e48310be099afd0dca0f28778d0024318b339b75e2689f70128"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "36218345b9ce4aaf50b5df1642c00ac5caa744069e952eb6008a9a57a37dbbdc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 F8 48 83 E8 01 0F B6 00 3C 0D 75 0B 48 8B 45 F8 0F B6 00 }

	condition:
		all of them
}