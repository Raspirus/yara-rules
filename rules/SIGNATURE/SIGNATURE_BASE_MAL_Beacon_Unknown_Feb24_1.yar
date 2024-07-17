import "pe"


rule SIGNATURE_BASE_MAL_Beacon_Unknown_Feb24_1 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709 "
		author = "Florian Roth"
		id = "9299fd44-5327-5a73-8299-108b710cb16e"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L249-L268"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fd6ebc6676d677d6bc19398026eee7b7d2f9727ba7a3c79d1e970a6dc19548aa"
		score = 75
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "6e8f83c88a66116e1a7eb10549542890d1910aee0000e3e70f6307aae21f9090"
		hash2 = "b0adf3d58fa354dbaac6a2047b6e30bc07a5460f71db5f5975ba7b96de986243"
		hash3 = "c0f7970bed203a5f8b2eca8929b4e80ba5c3276206da38c4e0a4445f648f3cec"

	strings:
		$s1 = "Driver.dll" wide fullword
		$s2 = "X l.dlT" ascii fullword
		$s3 = "$928c7481-dd27-8e23-f829-4819aefc728c" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 3 of ($s*)
}