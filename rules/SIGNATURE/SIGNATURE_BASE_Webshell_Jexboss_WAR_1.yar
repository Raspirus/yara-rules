
rule SIGNATURE_BASE_Webshell_Jexboss_WAR_1 : FILE
{
	meta:
		description = "Detects JexBoss versions in WAR form"
		author = "Florian Roth (Nextron Systems)"
		id = "0973f6cf-8a5f-5449-812e-36aa6b9939df"
		date = "2018-11-08"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-webshells.yar#L9874-L9897"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ee9cb22496d2e36d215caa9c7e295b41cb8434322a0097bbc3d1a365dce0c156"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "6271775ab144ce9bb9138bf054b149b5813d3beb96338993c6de35330f566092"
		hash2 = "6f14a63c3034d3762da8b3ad4592a8209a0c88beebcb9f9bd11b40e879f74eaf"

	strings:
		$ = "jbossass" fullword ascii
		$ = "jexws.jsp" fullword ascii
		$ = "jexws.jspPK" fullword ascii
		$ = "jexws1.jsp" fullword ascii
		$ = "jexws1.jspPK" fullword ascii
		$ = "jexws2.jsp" fullword ascii
		$ = "jexws2.jspPK" fullword ascii
		$ = "jexws3.jsp" fullword ascii
		$ = "jexws3.jspPK" fullword ascii
		$ = "jexws4.jsp" fullword ascii
		$ = "jexws4.jspPK" fullword ascii

	condition:
		uint16(0)==0x4b50 and filesize <4KB and 1 of them
}