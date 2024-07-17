
rule SIGNATURE_BASE_SUSP_DOC_RTF_Externalresource_EMAIL_Jun22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation inside e-mail attachment"
		author = "Christian Burkard"
		id = "3ddc838c-8520-5572-9652-8cb823f83e27"
		date = "2022-06-01"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L190-L216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "73e76bd80f77640c0d8d47ebb7903eb9cc23336fbe653e7d008cae6a0de7c45b"
		score = 70
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$sa1 = "PFJlbGF0aW9uc2hpcH" ascii
		$sa2 = "xSZWxhdGlvbnNoaXBz" ascii
		$sa3 = "8UmVsYXRpb25zaGlwc" ascii
		$sb1 = "VGFyZ2V0TW9kZT0iRXh0ZXJuYWwi" ascii
		$sb2 = "RhcmdldE1vZGU9IkV4dGVybmFsI" ascii
		$sb3 = "UYXJnZXRNb2RlPSJFeHRlcm5hbC" ascii
		$sc1 = "Lmh0bWwhI" ascii
		$sc2 = "5odG1sIS" ascii
		$sc3 = "uaHRtbCEi" ascii

	condition:
		filesize <400KB and 1 of ($sa*) and 1 of ($sb*) and 1 of ($sc*)
}