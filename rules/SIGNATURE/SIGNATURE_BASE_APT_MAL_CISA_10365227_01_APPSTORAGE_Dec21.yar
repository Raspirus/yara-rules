
rule SIGNATURE_BASE_APT_MAL_CISA_10365227_01_APPSTORAGE_Dec21 : APPSTORAGE FILE
{
	meta:
		description = "Detects AppStorage ntstatus msexch samples"
		author = "CISA Code & Media Analysis"
		id = "a44c5609-980f-5961-921c-6b1824cdd49c"
		date = "2021-12-23"
		modified = "2021-12-24"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_stealer_cisa_ar22_277a.yar#L25-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6a46bc4efa1f22d9fc65d946dbaa7b94de6074e65c228373bb6001f152d5b603"
		score = 80
		quality = 85
		tags = "APPSTORAGE, FILE"
		family = "APPSTORAGE"
		hash1 = "157a0ffd18e05bfd90a4ec108e5458cbde01015e3407b3964732c9d4ceb71656"
		hash2 = "30191b3badf3cdbc65d0ffeb68e0f26cef10a41037351b0f562ab52fce7432cc"

	strings:
		$s1 = "026B924DD52F8BE4A3FEE8575DC"
		$s2 = "GetHDDId"
		$s3 = "AppStorage"
		$s4 = "AppDomain"
		$s5 = "$1e3e5580-d264-4c30-89c9-8933c948582c"
		$s6 = "hrjio2mfsdlf235d" wide

	condition:
		uint16(0)==0x5a4d and all of them
}