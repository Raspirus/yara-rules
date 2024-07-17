rule SIGNATURE_BASE_SUSP_MAL_Signingcert_Feb24_1 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects PE files signed with a certificate used to sign malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		id = "f25ea77a-1b4e-5c13-9117-eedf0c20335a"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L166-L184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "824efe1fa441322d891805df9a1637ebb44d18889572604acc125bf79a2d1083"
		score = 75
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "37a39fc1feb4b14354c4d4b279ba77ba51e0d413f88e6ab991aad5dd6a9c231b"
		hash2 = "e8c48250cf7293c95d9af1fb830bb8a5aaf9cfb192d8697d2da729867935c793"

	strings:
		$s1 = "Wisdom Promise Security Technology Co." ascii
		$s2 = "Globalsign TSA for CodeSign1" ascii
		$s3 = { 5D AC 0B 6C 02 5A 4B 21 89 4B A3 C2 }

	condition:
		uint16(0)==0x5a4d and filesize <70000KB and all of them
}