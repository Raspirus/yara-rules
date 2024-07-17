
rule SIGNATURE_BASE_HKTL_EXPL_POC_PY_Sharepoint_CVE_2023_29357_Sep23_1 : CVE_2023_29357 FILE
{
	meta:
		description = "Detects a Python POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
		author = "Florian Roth"
		id = "2be524ab-f360-56b8-9ce3-e15036855c67"
		date = "2023-10-01"
		modified = "2023-10-01"
		reference = "https://github.com/Chocapikk/CVE-2023-29357"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_sharepoint_cve_2023_29357.yar#L22-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fec7762ab23ba5ee9e793000d080b1d64b93157c6ead9e6939ccfb3c168dd360"
		score = 80
		quality = 85
		tags = "CVE-2023-29357, FILE"

	strings:
		$x1 = "encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')"

	condition:
		filesize <30KB and $x1
}