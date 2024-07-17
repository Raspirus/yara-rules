rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Indicators_Feb24 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects Lockbit ransomware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		id = "108430c8-4fe5-58a1-b709-539b257c120c"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L208-L228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e4cd6b1a1bc57bf25c71f6bc228f45e4a996f9d9d391aeb3dda9c7d7857610bc"
		score = 75
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "a50d9954c0a50e5804065a8165b18571048160200249766bfa2f75d03c8cb6d0"

	strings:
		$op1 = { 76 c1 95 8b 18 00 93 56 bf 2b 88 71 4c 34 af b1 a5 e9 77 46 c3 13 }
		$op2 = { e0 02 10 f7 ac 75 0e 18 1b c2 c1 98 ac 46 }
		$op3 = { 8b c6 ab 53 ff 15 e4 57 42 00 ff 45 fc eb 92 ff 75 f8 ff 15 f4 57 42 00 }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="914685b69f2ac2ff61b6b0f1883a054d" or 2 of them ) or all of them
}