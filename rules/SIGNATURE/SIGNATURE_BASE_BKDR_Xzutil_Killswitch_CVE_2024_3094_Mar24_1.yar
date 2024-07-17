rule SIGNATURE_BASE_BKDR_Xzutil_Killswitch_CVE_2024_3094_Mar24_1 : CVE_2024_3094
{
	meta:
		description = "Detects kill switch used by the backdoored XZ library (xzutil) CVE-2024-3094."
		author = "Florian Roth"
		id = "0d28bec4-1d3a-5af0-9e9e-49486fcc62e1"
		date = "2024-03-30"
		modified = "2024-04-24"
		reference = "https://gist.github.com/q3k/af3d93b6a1f399de28fe194add452d01?permalink_comment_id=5006558#gistcomment-5006558"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/bkdr_xz_util_cve_2024_3094.yar#L48-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b2024d4b8346c4f74524bb7f3c6b2850684c19471a00e6fa60fff1c41e4a86b6"
		score = 85
		quality = 85
		tags = "CVE-2024-3094"

	strings:
		$x1 = "yolAbejyiejuvnup=Evjtgvsh5okmkAvj"

	condition:
		$x1
}