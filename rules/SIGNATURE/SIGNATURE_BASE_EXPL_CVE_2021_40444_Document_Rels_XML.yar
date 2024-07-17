
rule SIGNATURE_BASE_EXPL_CVE_2021_40444_Document_Rels_XML : CVE_2021_40444 FILE
{
	meta:
		description = "Detects indicators found in weaponized documents that exploit CVE-2021-40444"
		author = "Jeremy Brown / @alteredbytes"
		id = "812bb68e-71ea-5a9a-8d39-ab99fdaa6c58"
		date = "2021-09-10"
		modified = "2023-12-05"
		reference = "https://twitter.com/AlteredBytes/status/1435811407249952772"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_cve_2021_40444.yar#L6-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b05c3b33c3cab2c9109d808ed197758bc987f07beee77e1f61094715e0c1a1e7"
		score = 75
		quality = 85
		tags = "CVE-2021-40444, FILE"

	strings:
		$b1 = "/relationships/oleObject" ascii
		$b2 = "/relationships/attachedTemplate" ascii
		$c1 = "Target=\"mhtml:http" nocase
		$c2 = "!x-usc:http" nocase
		$c3 = "TargetMode=\"External\"" nocase

	condition:
		uint32(0)==0x6D783F3C and filesize <10KB and 1 of ($b*) and all of ($c*)
}