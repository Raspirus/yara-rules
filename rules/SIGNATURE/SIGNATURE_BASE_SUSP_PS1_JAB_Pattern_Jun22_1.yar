rule SIGNATURE_BASE_SUSP_PS1_JAB_Pattern_Jun22_1 : FILE
{
	meta:
		description = "Detects suspicious UTF16 and Base64 encoded PowerShell code that starts with a $ sign and a single char variable"
		author = "Florian Roth (Nextron Systems)"
		id = "9ecca7d9-3b63-5615-a223-5efa1c53510e"
		date = "2022-06-10"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_ps_jab.yar#L2-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9ad61dca5c945ed87642668e3b834b12c813af244437903a5abb5c69459b9456"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$xc1 = { 4a 41 42 ?? 41 43 41 41 50 51 41 67 41 }
		$xc2 = { 4a 00 41 00 42 00 ?? 00 41 00 43 00 41 00 41 00 50 00 51 00 41 00 67 00 41 }
		$xc3 = { 4a 41 42 ?? 41 44 30 41 }
		$xc4 = { 4a 00 41 00 42 00 ?? 00 41 00 44 00 30 00 41 }

	condition:
		filesize <30MB and 1 of them
}