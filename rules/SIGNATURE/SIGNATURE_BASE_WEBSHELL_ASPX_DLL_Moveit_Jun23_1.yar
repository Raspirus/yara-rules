rule SIGNATURE_BASE_WEBSHELL_ASPX_DLL_Moveit_Jun23_1 : FILE
{
	meta:
		description = "Detects compiled ASPX web shells found being used in MOVEit Transfer exploitation"
		author = "Florian Roth"
		id = "47db8602-9a9e-5efc-b8b9-fbc4f3c8d4e9"
		date = "2023-06-01"
		modified = "2023-12-05"
		reference = "https://www.trustedsec.com/blog/critical-vulnerability-in-progress-moveit-transfer-technical-analysis-and-recommendations/?utm_content=251159938&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vuln_moveit_0day_jun23.yar#L2-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "47c2ec1e833852941434586b61d6f435b9acb32b2ff48e0a9e8006e0f9ff8056"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "6cbf38f5f27e6a3eaf32e2ac73ed02898cbb5961566bb445e3c511906e2da1fa"

	strings:
		$x1 = "human2_aspx" ascii fullword
		$x2 = "X-siLock-Comment" wide
		$x3 = "x-siLock-Step1" wide
		$a1 = "MOVEit.DMZ.Core.Data" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <40KB and (1 of ($x*) and $a1) or all of them
}