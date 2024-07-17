rule SIGNATURE_BASE_MAL_WAR_Ivanti_EPMM_Mobileiron_Mi_War_Aug23 : CVE_2023_35078 FILE
{
	meta:
		description = "Detects WAR file found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
		author = "Florian Roth"
		id = "cd16cf29-a90d-5c3f-b66f-e9264dbf79fb"
		date = "2023-08-01"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_ivanti_epmm_mobileiron_cve_2023_35078.yar#L16-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0083727e34118d628c8507459bfb7f949f11af8197e201066e29e263e2c3f944"
		score = 85
		quality = 85
		tags = "CVE-2023-35078, FILE"
		hash1 = "6255c75e2e52d779da39367e7a7d4b8d1b3c9c61321361952dcc05819251a127"

	strings:
		$s1 = "logsPaths.txt" ascii fullword
		$s2 = "keywords.txtFirefox" ascii

	condition:
		uint16(0)==0x4b50 and filesize <20KB and all of them
}