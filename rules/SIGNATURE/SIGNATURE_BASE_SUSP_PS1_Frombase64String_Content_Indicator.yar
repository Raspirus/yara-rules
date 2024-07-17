
rule SIGNATURE_BASE_SUSP_PS1_Frombase64String_Content_Indicator : FILE
{
	meta:
		description = "Detects suspicious base64 encoded PowerShell expressions"
		author = "Florian Roth (Nextron Systems)"
		id = "326c83ff-5d21-508f-b935-03ccdab6efa7"
		date = "2020-01-25"
		modified = "2024-04-03"
		reference = "https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_powershell_susp.yar#L233-L284"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a9ec7a00e9faee5cc081a2bc86abf8027fcd3cfe590cdd4f2f99425b6723f23f"
		score = 65
		quality = 83
		tags = "FILE"

	strings:
		$ = "::FromBase64String(\"H4s" ascii wide
		$ = "::FromBase64String(\"TVq" ascii wide
		$ = "::FromBase64String(\"UEs" ascii wide
		$ = "::FromBase64String(\"JAB" ascii wide
		$ = "::FromBase64String(\"SUVY" ascii wide
		$ = "::FromBase64String(\"SQBFAF" ascii wide
		$ = "::FromBase64String(\"SQBuAH" ascii wide
		$ = "::FromBase64String(\"PAA" ascii wide
		$ = "::FromBase64String(\"cwBhA" ascii wide
		$ = "::FromBase64String(\"aWV4" ascii wide
		$ = "::FromBase64String(\"aQBlA" ascii wide
		$ = "::FromBase64String(\"R2V0" ascii wide
		$ = "::FromBase64String(\"dmFy" ascii wide
		$ = "::FromBase64String(\"dgBhA" ascii wide
		$ = "::FromBase64String(\"dXNpbm" ascii wide
		$ = "::FromBase64String(\"H4sIA" ascii wide
		$ = "::FromBase64String(\"Y21k" ascii wide
		$ = "::FromBase64String(\"Qzpc" ascii wide
		$ = "::FromBase64String(\"Yzpc" ascii wide
		$ = "::FromBase64String(\"IAB" ascii wide
		$ = "::FromBase64String('H4s" ascii wide
		$ = "::FromBase64String('TVq" ascii wide
		$ = "::FromBase64String('UEs" ascii wide
		$ = "::FromBase64String('JAB" ascii wide
		$ = "::FromBase64String('SUVY" ascii wide
		$ = "::FromBase64String('SQBFAF" ascii wide
		$ = "::FromBase64String('SQBuAH" ascii wide
		$ = "::FromBase64String('PAA" ascii wide
		$ = "::FromBase64String('cwBhA" ascii wide
		$ = "::FromBase64String('aWV4" ascii wide
		$ = "::FromBase64String('aQBlA" ascii wide
		$ = "::FromBase64String('R2V0" ascii wide
		$ = "::FromBase64String('dmFy" ascii wide
		$ = "::FromBase64String('dgBhA" ascii wide
		$ = "::FromBase64String('dXNpbm" ascii wide
		$ = "::FromBase64String('H4sIA" ascii wide
		$ = "::FromBase64String('Y21k" ascii wide
		$ = "::FromBase64String('Qzpc" ascii wide
		$ = "::FromBase64String('Yzpc" ascii wide
		$ = "::FromBase64String('IAB" ascii wide

	condition:
		filesize <5000KB and 1 of them
}