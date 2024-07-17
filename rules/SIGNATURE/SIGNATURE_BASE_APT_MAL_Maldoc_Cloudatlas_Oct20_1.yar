
rule SIGNATURE_BASE_APT_MAL_Maldoc_Cloudatlas_Oct20_1 : FILE
{
	meta:
		description = "Detects unknown maldoc dropper noticed in October 2020"
		author = "Florian Roth (Nextron Systems)"
		id = "e7caf2b2-caf2-5984-a792-8224f2641bda"
		date = "2020-10-13"
		modified = "2023-12-05"
		reference = "https://twitter.com/jfslowik/status/1316050637092651009"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cloudatlas.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "772bdd8ec89edf2054e675e9ecb321a7bfe0307a7086a4e5b65f8d8b8cf80ecc"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "7ba76b2311736dbcd4f2817c40dae78f223366f2404571cd16d6676c7a640d70"

	strings:
		$x1 = "https://msofficeupdate.org" wide

	condition:
		uint16(0)==0xcfd0 and filesize <300KB and 1 of ($x*)
}