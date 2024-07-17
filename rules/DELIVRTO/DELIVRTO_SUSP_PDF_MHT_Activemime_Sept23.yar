
rule DELIVRTO_SUSP_PDF_MHT_Activemime_Sept23 : FILE
{
	meta:
		description = "Presence of MHT ActiveMime within PDF for polyglot file"
		author = "delivr.to"
		id = "fbac1371-bad4-5751-a5c4-ce6c270fb83e"
		date = "2023-09-04"
		modified = "2023-09-04"
		reference = "https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html"
		source_url = "https://github.com/delivr-to/detections/blob/d2dcf7e9566e39655994aa0c5f8fb7a94cae2984/yara-rules/pdf_mht_activemime.yar#L1-L19"
		license_url = "N/A"
		logic_hash = "af1450f649de6daec242f11e3b3c35305d3127fac4ef719a4ddb4edab3ae3651"
		score = 70
		quality = 78
		tags = "FILE"

	strings:
		$mht0 = "mime" ascii nocase
		$mht1 = "content-location:" ascii nocase
		$mht2 = "content-type:" ascii nocase
		$act = "edit-time-data" ascii nocase

	condition:
		uint32(0)==0x46445025 and all of ($mht*) and $act
}