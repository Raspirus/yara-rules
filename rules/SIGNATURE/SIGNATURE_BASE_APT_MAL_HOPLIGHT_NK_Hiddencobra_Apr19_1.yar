rule SIGNATURE_BASE_APT_MAL_HOPLIGHT_NK_Hiddencobra_Apr19_1 : FILE
{
	meta:
		description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
		author = "Florian Roth (Nextron Systems)"
		id = "923a0812-f375-5c0c-a22c-fc71ddcad4e3"
		date = "2019-04-13"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hidden_cobra.yar#L124-L137"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6cd036129ea54f4e3a2c52bf9ebd04e2d368e737cf83ca34a8feb79ea477a3af"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "d77fdabe17cdba62a8e728cbe6c740e2c2e541072501f77988674e07a05dfb39"

	strings:
		$s1 = "www.naver.com" fullword ascii
		$s2 = "PolarSSL Test CA0" fullword ascii

	condition:
		filesize <1000KB and all of them
}