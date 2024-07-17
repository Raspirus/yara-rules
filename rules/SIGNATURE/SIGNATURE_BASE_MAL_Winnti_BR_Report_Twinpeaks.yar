rule SIGNATURE_BASE_MAL_Winnti_BR_Report_Twinpeaks : FILE
{
	meta:
		description = "Detects Winnti samples"
		author = "@br_data repo"
		id = "2e4e2b88-fdb4-5adc-8192-a304d71ca851"
		date = "2019-07-24"
		modified = "2023-12-05"
		reference = "https://github.com/br-data/2019-winnti-analyse"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_br.yar#L3-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "76457f5aa4cc4bf4f43ffbaa60d63006455977e881f1d74b845835c505a93fed"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$cooper = "Cooper"
		$pattern = { e9 ea eb ec ed ee ef f0}

	condition:
		uint16(0)==0x5a4d and $cooper and ($pattern in (@cooper[1]..@cooper[1]+100))
}