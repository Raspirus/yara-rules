
rule SIGNATURE_BASE_MAL_WAR_Ivanti_EPMM_Mobileiron_Logclear_JAVA_Aug23 : CVE_2023_35078 FILE
{
	meta:
		description = "Detects LogClear.class found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
		author = "Florian Roth"
		id = "e1ef3bf3-0107-5ba6-a49f-71e079851a4f"
		date = "2023-08-01"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_ivanti_epmm_mobileiron_cve_2023_35078.yar#L34-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c42c2eca784d7089aab56addca11bad658a4a6c34a81ae823bd0c3dad41a1c99"
		score = 80
		quality = 85
		tags = "CVE-2023-35078, FILE"
		hash1 = "deb381c25d7a511b9eb936129eeba2c0341cff7f4bd2168b05e40ab2ee89225e"

	strings:
		$s1 = "logsPaths.txt" ascii fullword
		$s2 = "log file: %s, not read" ascii fullword
		$s3 = "/tmp/.time.tmp" ascii fullword
		$s4 = "readKeywords" ascii fullword
		$s5 = "\"----------------  ----------------" ascii fullword

	condition:
		uint16(0)==0xfeca and filesize <20KB and 4 of them or all of them
}