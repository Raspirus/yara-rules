rule SIGNATURE_BASE_Crime_Ole_Loadswf_Cve_2018_4878 : PURPORTED_NORTH_KOREAN_ACTORS CVE_2018_4878 FILE
{
	meta:
		description = "Detects CVE-2018-4878"
		author = "Vitali Kremez, Flashpoint"
		id = "44797bbc-693b-5fcb-a4a4-4ebf3f4da725"
		date = "2024-01-01"
		modified = "2023-12-05"
		reference = "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_ole_loadswf_cve_2018_4878.yar#L2-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "716cad0c5a12cc360522e2649c7870a493bef4bec3d55c3a3e235f3a85c02a56"
		score = 75
		quality = 85
		tags = "PURPORTED NORTH KOREAN ACTORS, CVE-2018-4878, FILE"
		vuln_type = "Remote Code Execution"
		vuln_impact = "Use-after-free"
		affected_versions = "Adobe Flash 28.0.0.137 and earlier versions"
		mitigation0 = "Implement Protected View for Office documents"
		mitigation1 = "Disable Adobe Flash"
		weaponization = "Embedded in Microsoft Office first payloads"
		actor = "Purported North Korean actors"

	strings:
		$header = "rdf:RDF" wide ascii
		$title = "Adobe Flex" wide ascii
		$pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii
		$s0 = "URLRequest" wide ascii
		$s1 = "URLLoader" wide ascii
		$s2 = "loadswf" wide ascii
		$s3 = "myUrlReqest" wide ascii

	condition:
		filesize <500KB and all of ($header*) and all of ($title*) and 3 of ($s*) or all of ($pdb*) and all of ($header*) and 1 of ($s*)
}