
rule SIGNATURE_BASE_APT_MAL_CISA_10365227_03_Clientuploader_Dec21 : FILE
{
	meta:
		description = "Detects ClientUploader onedrv"
		author = "CISA Code & Media Analysis"
		id = "4eeadb28-9312-5602-932a-36acb48772f4"
		date = "2021-12-23"
		modified = "2021-12-24"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_stealer_cisa_ar22_277a.yar#L4-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "76f552b2416ae2426b73a321485f34a611c2a3c1ca35791bc9f1834072dc28be"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "84164e1e8074c2565d3cd178babd93694ce54811641a77ffdc8d1084dd468afb"

	strings:
		$s1 = "Decoder2"
		$s2 = "ClientUploader"
		$s3 = "AppDomain"
		$s4 = { 5F 49 73 52 65 70 47 ?? 44 65 63 6F 64 65 72 73 }
		$s5 = "LzmaDecoder"
		$s6 = "$ee1b3f3b-b13c-432e-a461-e52d273896a7"

	condition:
		uint16(0)==0x5a4d and all of them
}