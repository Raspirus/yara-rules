
rule SIGNATURE_BASE_LOG_EXPL_Ivanti_EPMM_Mobileiron_Core_CVE_2023_35078_Jul23_1 : CVE_2023_35078
{
	meta:
		description = "Detects the successful exploitation of Ivanti Endpoint Manager Mobile (EPMM) / MobileIron Core CVE-2023-35078"
		author = "Florian Roth"
		id = "44cca0b5-3851-5786-82fd-ce3ccb566453"
		date = "2023-07-25"
		modified = "2023-12-05"
		reference = "Ivanti Endpoint Manager Mobile (EPMM) CVE-2023-35078 - Analysis Guidance"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_ivanti_epmm_mobileiron_cve_2023_35078.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ebc59032b7450aa438ca30170560c95550cda6ff7774b8ce1486309716da9e6c"
		score = 75
		quality = 85
		tags = "CVE-2023-35078"

	strings:
		$xr1 = /\/mifs\/aad\/api\/v2\/[^\n]{1,300} 200 [1-9][0-9]{0,60} /

	condition:
		$xr1
}