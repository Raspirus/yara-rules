
rule SIGNATURE_BASE_SUSP_OBFUSC_Indiators_XML_Officedoc_Sep21_2 : WINDOWS CVE FILE
{
	meta:
		description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
		author = "Florian Roth (Nextron Systems)"
		id = "c3c5ec4f-5d2a-523c-bd4b-b75c04bac87d"
		date = "2021-09-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_cve_2021_40444.yar#L83-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "82c70e0f0b72a57302e5853cc53ae18dbb0bc8dabdfd27b473a7664b2fc5e874"
		score = 65
		quality = 85
		tags = "WINDOWS, CVE, FILE"

	strings:
		$h1 = "<?xml " ascii wide
		$a1 = "Target" ascii wide
		$a2 = "TargetMode" ascii wide
		$xml_e = "&#x0000" ascii wide

	condition:
		filesize <500KB and all of them
}