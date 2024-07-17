rule SIGNATURE_BASE_LOG_EXPL_Adselfservice_CVE_2021_40539_ADSLOG_Sep21 : LOG CVE_2021_40539 FILE
{
	meta:
		description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
		author = "Florian Roth (Nextron Systems)"
		id = "156317c6-e726-506d-8b07-4f74dae2807f"
		date = "2021-09-20"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_adselfservice_cve_2021_40539.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "49b7857187c15f48e928747266adca44c227964cef72914616ea269b0e88fe73"
		score = 70
		quality = 85
		tags = "LOG, CVE-2021-40539, FILE"

	strings:
		$x1 = "Java traceback errors that include references to NullPointerException in addSmartCardConfig or getSmartCardConfig" ascii wide

	condition:
		filesize <50MB and 1 of them
}