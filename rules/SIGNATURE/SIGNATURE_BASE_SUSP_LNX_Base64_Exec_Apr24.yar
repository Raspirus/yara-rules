
rule SIGNATURE_BASE_SUSP_LNX_Base64_Exec_Apr24 : SCRIPT CVE_2024_3400
{
	meta:
		description = "Detects suspicious base64 encoded shell commands (as seen in Palo Alto CVE-2024-3400 exploitation)"
		author = "Christian Burkard"
		id = "2da3d050-86b0-5903-97eb-c5f39ce4f3a3"
		date = "2024-04-18"
		modified = "2024-04-24"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L81-L96"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f84556970f2d90eaea89a03ae48518592f14eecd60ef4cc811988de451d5375c"
		score = 75
		quality = 85
		tags = "SCRIPT, CVE-2024-3400"

	strings:
		$s1 = "curl http://" base64
		$s2 = "wget http://" base64
		$s3 = ";chmod 777 " base64
		$s4 = "/tmp/" base64

	condition:
		all of them
}