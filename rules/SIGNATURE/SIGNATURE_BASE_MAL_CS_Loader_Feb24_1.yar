rule SIGNATURE_BASE_MAL_CS_Loader_Feb24_1 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects Cobalt Strike malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		id = "6c9914a4-b079-5a39-9d3b-7b9a2b54dc2b"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L186-L206"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ae0e25c2dda1b727978977c674e834cd659661c597d88395a6f46ad5a179e9f0"
		score = 75
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "0a492d89ea2c05b1724a58dd05b7c4751e1ffdd2eab3a2f6a7ebe65bf3fdd6fe"

	strings:
		$s1 = "Dll_x86.dll" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (pe.exports("UpdateSystem") and (pe.imphash()=="0dc05c4c21a86d29f1c3bf9cc5b712e0" or $s1))
}