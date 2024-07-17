
rule SIGNATURE_BASE_HKTL_EXPL_POC_NET_Sharepoint_CVE_2023_29357_Sep23_1 : CVE_2023_29357 FILE
{
	meta:
		description = "Detects a C# POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
		author = "Florian Roth"
		id = "aa6aeb00-b162-538c-a670-cbff525dd8f1"
		date = "2023-10-01"
		modified = "2023-12-05"
		reference = "https://github.com/LuemmelSec/CVE-2023-29357"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_sharepoint_cve_2023_29357.yar#L37-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cf621cc9c5074f531df61623b09db68478e94ae6a9a7acc26aa8d9dde79bd30c"
		score = 80
		quality = 85
		tags = "CVE-2023-29357, FILE"

	strings:
		$x1 = "{f22d2de0-606b-4d16-98d5-421f3f1ba8bc}" ascii wide
		$x2 = "{F22D2DE0-606B-4D16-98D5-421F3F1BA8BC}" ascii wide
		$s1 = "Bearer"
		$s2 = "hashedprooftoken"
		$s3 = "/_api/web/"
		$s4 = "X-PROOF_TOKEN"
		$s5 = "00000003-0000-0ff1-ce00-000000000000"
		$s6 = "IsSiteAdmin"

	condition:
		uint16(0)==0x5a4d and filesize <800KB and (1 of ($x*) or all of ($s*))
}