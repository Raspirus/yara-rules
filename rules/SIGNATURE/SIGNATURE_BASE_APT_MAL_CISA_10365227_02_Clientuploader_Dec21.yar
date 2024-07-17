
rule SIGNATURE_BASE_APT_MAL_CISA_10365227_02_Clientuploader_Dec21 : FILE
{
	meta:
		description = "Detects ClientUploader_mqsvn"
		author = "CISA Code & Media Analysis"
		id = "84351df9-e225-5c3f-9385-523246681a97"
		date = "2021-12-23"
		modified = "2021-12-24"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_stealer_cisa_ar22_277a.yar#L48-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f9f82b4577568d0bd60bac0d3132ed7ffcb338f508a8689f3126f3d2440432ef"
		score = 80
		quality = 81
		tags = "FILE"
		hash1 = "3585c3136686d7d48e53c21be61bb2908d131cf81b826acf578b67bb9d8e9350"

	strings:
		$s1 = "UploadSmallFileWithStopWatch"
		$s2 = "UploadPartWithStopwatch"
		$s3 = "AppVClient"
		$s4 = "ClientUploader"
		$s5 = { 46 69 6C 65 43 6F 6E 74 61 69 6E 65 72 2E 46 69 6C 65 41 72 63 68 69 76 65 }
		$s6 = { 4F 6E 65 44 72 69 76 65 43 6C 69 65 6E 74 2E 4F 6E 65 44 72 69 76 65 }

	condition:
		uint16(0)==0x5a4d and all of them
}