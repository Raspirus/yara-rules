
rule SIGNATURE_BASE_EXPL_XML_Encoded_CVE_2021_40444 : CVE_2021_40444 FILE
{
	meta:
		description = "Detects possible CVE-2021-40444 with no encoding, HTML/XML entity (and hex notation) encoding, or all 3"
		author = "James E.C, Proofpoint"
		id = "4bf9ec64-c662-5c8f-9e58-12a7412ef07d"
		date = "2021-09-18"
		modified = "2021-09-19"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_cve_2021_40444.yar#L44-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "13de9f39b1ad232e704b5e0b5051800fcd844e9f661185ace8287a23e9b3868e"
		hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
		logic_hash = "feaeadd8e7e262f191ea0c2f85377531208262e5ac19d6706703e62cf8b4ec90"
		score = 70
		quality = 85
		tags = "CVE-2021-40444, FILE"

	strings:
		$h1 = "<?xml " ascii wide
		$t_xml_r = /Target[\s]{0,20}=[\s]{0,20}\["']([Mm]|&#(109|77|x6d|x4d);)([Hh]|&#(104|72|x68|x48);)([Tt]|&#(116|84|x74|x54);)([Mm]|&#(109|77|x6d|x4d);)([Ll]|&#(108|76|x6c|x4c);)(:|&#58;|&#x3a)/
		$t_mode_r = /TargetMode[\s]{0,20}=[\s]{0,20}\["']([Ee]|&#(x45|x65|69|101);)([Xx]|&#(x58|x78|88|120);)([Tt]|&#(x74|x54|84|116);)/

	condition:
		filesize <500KB and $h1 and all of ($t_*)
}