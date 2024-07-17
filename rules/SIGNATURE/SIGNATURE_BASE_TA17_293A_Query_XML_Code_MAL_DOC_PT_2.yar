rule SIGNATURE_BASE_TA17_293A_Query_XML_Code_MAL_DOC_PT_2 : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "other (modified by Florian Roth)"
		id = "82b0f28a-94b6-52ab-8fd6-cdc05823ac34"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_293A.yar#L95-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8d4c1b23aa8323fa9ddec362bb36e13e5f992883fbf7936b34cf03fe62ee6127"
		score = 75
		quality = 85
		tags = "FILE"
		name = "Query_XML_Code_MAL_DOC_PT_2"

	strings:
		$dir1 = "word/_rels/settings.xml.rels"
		$bytes = {8c 90 cd 4e eb 30 10 85 d7}

	condition:
		uint32(0)==0x04034b50 and $dir1 and $bytes
}