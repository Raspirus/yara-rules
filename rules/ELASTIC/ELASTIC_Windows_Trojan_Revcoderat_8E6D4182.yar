
rule ELASTIC_Windows_Trojan_Revcoderat_8E6D4182 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Revcoderat (Windows.Trojan.Revcoderat)"
		author = "Elastic Security"
		id = "8e6d4182-4ea8-4d4c-ad3a-d16b42e387f4"
		date = "2021-09-02"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Revcoderat.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "77732e74850050bb6f935945e510d32a0499d820fa1197752df8bd01c66e8210"
		logic_hash = "35626d752b291e343350534aece35f1d875068c2c050d12312a60e67753c71e1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bc259d888e913dffb4272e2f871592238eb78922989d30ac4dc23cdeb988cc78"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "PLUGIN_PROCESS_REVERSE_PROXY: Plugin already exists, skipping download!" ascii fullword
		$a2 = "TARGET_HOST_UPDATE(): Sync successful!" ascii fullword
		$a3 = "WEBCAM_ACTIVATE: Plugin already exists, skipping download!" ascii fullword
		$a4 = "send_keylog_get" ascii fullword

	condition:
		all of them
}