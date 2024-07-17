
rule SIGNATURE_BASE_SUSP_Doc_RTF_Ole2Link_EMAIL_Jun22 : FILE
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources inside e-mail attachments"
		author = "Christian Burkard"
		id = "48cde505-3ce4-52ef-b338-0c08ac4f63de"
		date = "2022-06-01"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L129-L188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "4abc20e5130b59639e20bd6b8ad759af18eb284f46e99a5cc6b4f16f09456a68"
		logic_hash = "fcbb3e32762f8c67b5b226e8095b767d630f8c118521a82fc22f9a3cc272b794"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$sa1 = "XG9iamRhdG" ascii
		$sa2 = "xvYmpkYXRh" ascii
		$sa3 = "cb2JqZGF0Y" ascii
		$sb1 = "NGY0YzQ1MzI0YzY5NmU2Y" ascii
		$sb2 = "RmNGM0NTMyNGM2OTZlNm" ascii
		$sb3 = "0ZjRjNDUzMjRjNjk2ZTZi" ascii
		$sb4 = "NEY0QzQ1MzI0QzY5NkU2Q" ascii
		$sb5 = "RGNEM0NTMyNEM2OTZFNk" ascii
		$sb6 = "0RjRDNDUzMjRDNjk2RTZC" ascii
		$sc1 = "ZDBjZjExZTBhMWIxMWFlM" ascii
		$sc2 = "QwY2YxMWUwYTFiMTFhZT" ascii
		$sc3 = "kMGNmMTFlMGExYjExYWUx" ascii
		$sc4 = "RDBDRjExRTBBMUIxMUFFM" ascii
		$sc5 = "QwQ0YxMUUwQTFCMTFBRT" ascii
		$sc6 = "EMENGMTFFMEExQjExQUUx" ascii
		$x1 = "NjgwMDc0MDA3NDAwNzAwMDNhMDAyZjAwMmYwM" ascii
		$x2 = "Y4MDA3NDAwNzQwMDcwMDAzYTAwMmYwMDJmMD" ascii
		$x3 = "2ODAwNzQwMDc0MDA3MDAwM2EwMDJmMDAyZjAw" ascii
		$x4 = "NjgwMDc0MDA3NDAwNzAwMDNBMDAyRjAwMkYwM" ascii
		$x5 = "Y4MDA3NDAwNzQwMDcwMDAzQTAwMkYwMDJGMD" ascii
		$x6 = "2ODAwNzQwMDc0MDA3MDAwM0EwMDJGMDAyRjAw" ascii
		$x7 = "NjgwMDc0MDA3NDAwNzAwMDczMDAzYTAwMmYwMDJmMD" ascii
		$x8 = "Y4MDA3NDAwNzQwMDcwMDA3MzAwM2EwMDJmMDAyZjAw" ascii
		$x9 = "2ODAwNzQwMDc0MDA3MDAwNzMwMDNhMDAyZjAwMmYwM" ascii
		$x10 = "NjgwMDc0MDA3NDAwNzAwMDczMDAzQTAwMkYwMDJGMD" ascii
		$x11 = "Y4MDA3NDAwNzQwMDcwMDA3MzAwM0EwMDJGMDAyRjAw" ascii
		$x12 = "2ODAwNzQwMDc0MDA3MDAwNzMwMDNBMDAyRjAwMkYwM" ascii
		$x13 = "NjYwMDc0MDA3MDAwM2EwMDJmMDAyZjAw" ascii
		$x14 = "Y2MDA3NDAwNzAwMDNhMDAyZjAwMmYwM" ascii
		$x15 = "2NjAwNzQwMDcwMDAzYTAwMmYwMDJmMD" ascii
		$x16 = "NjYwMDc0MDA3MDAwM0EwMDJGMDAyRjAw" ascii
		$x17 = "Y2MDA3NDAwNzAwMDNBMDAyRjAwMkYwM" ascii
		$x18 = "2NjAwNzQwMDcwMDAzQTAwMkYwMDJGMD" ascii

	condition:
		filesize <10MB and 1 of ($sa*) and 1 of ($sb*) and 1 of ($sc*) and 1 of ($x*)
}