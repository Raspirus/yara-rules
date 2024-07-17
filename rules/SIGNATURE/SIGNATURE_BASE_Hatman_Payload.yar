
rule SIGNATURE_BASE_Hatman_Payload : HATMAN
{
	meta:
		description = "Detects Hatman malware"
		author = "DHS/NCCIC/ICS-CERT"
		id = "9ef57fca-a536-5937-8510-b410f735a73e"
		date = "2017-12-19"
		modified = "2023-12-05"
		reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hatman.yar#L107-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9a6e5d2c2f2be35e6dc8b418e33419977460006923ecd9f029cacf51d8c0477a"
		score = 75
		quality = 85
		tags = "HATMAN"

	condition:
		(SIGNATURE_BASE_Hatman_Memcpy_PRIVATE and SIGNATURE_BASE_Hatman_Origcode_PRIVATE and SIGNATURE_BASE_Hatman_Mftmsr_PRIVATE) and not (SIGNATURE_BASE_Hatman_Origaddr_PRIVATE and SIGNATURE_BASE_Hatman_Loadoff_PRIVATE)
}