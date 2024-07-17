rule SIGNATURE_BASE_EXPL_Citrix_Netscaler_ADC_Forensicartifacts_CVE_2023_3519_Jul23_2 : CVE_2023_3519 FILE
{
	meta:
		description = "Detects forensic artifacts found after an exploitation of Citrix NetScaler ADC CVE-2023-3519"
		author = "Florian Roth"
		id = "471ce547-0133-5836-b9d1-02c932ecfd1e"
		date = "2023-07-21"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/sites/default/files/2023-07/aa23-201a_csa_threat_actors_exploiting_citrix-cve-2023-3519_to_implant_webshells.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar#L27-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "48d4225d0935084003f7a98c554d7c4722a91290dfe190001da52bce332b3f7d"
		score = 70
		quality = 85
		tags = "CVE-2023-3519, FILE"

	strings:
		$s1 = "tar -czvf - /var/tmp/all.txt" ascii fullword
		$s2 = "-out /var/tmp/test.tar.gz" ascii
		$s3 = "/test.tar.gz /netscaler/"

	condition:
		filesize <10MB and 1 of them
}