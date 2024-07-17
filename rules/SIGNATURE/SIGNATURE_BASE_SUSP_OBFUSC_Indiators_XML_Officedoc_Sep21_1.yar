
rule SIGNATURE_BASE_SUSP_OBFUSC_Indiators_XML_Officedoc_Sep21_1 : WINDOWS CVE FILE
{
	meta:
		description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
		author = "Florian Roth (Nextron Systems)"
		id = "ffcaf270-f574-5692-90e5-6776c34eb71b"
		date = "2021-09-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_cve_2021_40444.yar#L64-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "13de9f39b1ad232e704b5e0b5051800fcd844e9f661185ace8287a23e9b3868e"
		hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
		logic_hash = "fc8f0dd02460ab8f8cc6717c66eba51e6ed74881a48e92fd0bf978467dfb40e3"
		score = 65
		quality = 85
		tags = "WINDOWS, CVE, FILE"

	strings:
		$h1 = "<?xml " ascii wide
		$xml_e = "Target=\"&#" ascii wide
		$xml_mode_1 = "TargetMode=\"&#" ascii wide

	condition:
		filesize <500KB and $h1 and 1 of ($xml*)
}