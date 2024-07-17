rule SIGNATURE_BASE_APT_MAL_HOPLIGHT_NK_Hiddencobra_Apr19_2 : FILE
{
	meta:
		description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
		author = "Florian Roth (Nextron Systems)"
		id = "9c7fd381-272a-5cfc-a7ee-7f0f9221fa04"
		date = "2019-04-13"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hidden_cobra.yar#L139-L154"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "741d69b470ac230d502116ebd5f09bbf4bdbbbdd7e70b97a4bd5d3f2c8e148ef"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "70034b33f59c6698403293cdc28676c7daa8c49031089efa6eefce41e22dccb3"

	strings:
		$s1 = "%SystemRoot%\\System32\\svchost.exe -k mdnetuse" fullword ascii
		$s2 = "%s\\hid.dll" fullword ascii
		$s3 = "%Systemroot%\\System32\\" ascii
		$s4 = "SYSTEM\\CurrentControlSet\\services\\%s\\Parameters" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}