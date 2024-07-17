rule SIGNATURE_BASE_SUSP_OBFUSC_Powershell_True_Jun20_1 : FILE
{
	meta:
		description = "Detects indicators often found in obfuscated PowerShell scripts"
		author = "Florian Roth (Nextron Systems)"
		id = "e9bb870b-ad72-57d3-beff-2f84a81490eb"
		date = "2020-06-27"
		modified = "2023-12-05"
		reference = "https://github.com/corneacristian/mimikatz-bypass/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_powershell_obfuscation.yar#L57-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8f33762e6e93fcf6b423b34eb1abefae2ae91b51048303947f7c1601823630d7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = "${t`rue}" ascii nocase
		$ = "${tr`ue}" ascii nocase
		$ = "${tru`e}" ascii nocase
		$ = "${t`ru`e}" ascii nocase
		$ = "${tr`u`e}" ascii nocase
		$ = "${t`r`ue}" ascii nocase
		$ = "${t`r`u`e}" ascii nocase

	condition:
		filesize <6000KB and 1 of them
}