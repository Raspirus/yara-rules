
rule SIGNATURE_BASE_LOG_EXPL_Sharepoint_CVE_2023_29357_Sep23_1 : CVE_2023_29357
{
	meta:
		description = "Detects log entries that could indicate a successful exploitation of CVE-2023-29357 on Microsoft SharePoint servers with the published Python POC"
		author = "Florian Roth (with help from @LuemmelSec)"
		id = "9fa77216-c0d6-55e5-bbcc-adb9438ca456"
		date = "2023-09-28"
		modified = "2023-10-01"
		reference = "https://twitter.com/Gi7w0rm/status/1706764212704591953?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_sharepoint_cve_2023_29357.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "03e3a4715c8683dc8d03ad6720c1c9b40482bd0bfa3020aa1152565ec9ec929f"
		score = 70
		quality = 85
		tags = "CVE-2023-29357"

	strings:
		$xr1 = /GET [a-z\.\/_]{0,40}\/web\/(siteusers|currentuser) - (80|443) .{10,200} (python-requests\/[0-9\.]{3,8}|-) [^ ]{1,160} [^4]0[0-9] /

	condition:
		$xr1
}