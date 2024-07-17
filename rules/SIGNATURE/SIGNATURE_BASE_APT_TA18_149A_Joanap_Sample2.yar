rule SIGNATURE_BASE_APT_TA18_149A_Joanap_Sample2 : FILE
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		author = "Florian Roth (Nextron Systems)"
		id = "9f4e6e6c-ee2b-5fa3-bf85-5a1652b38c52"
		date = "2018-05-30"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta18_149A.yar#L36-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "046135e4a1161841835cd9d10e13224b440e914ce3f409bad84a1df2638a7d5f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "077d9e0e12357d27f7f0c336239e961a7049971446f7a3f10268d9439ef67885"

	strings:
		$s1 = "%SystemRoot%\\system32\\svchost.exe -k Wmmvsvc" fullword ascii
		$s2 = "%SystemRoot%\\system32\\svchost.exe -k SCardPrv" fullword ascii
		$s3 = "%SystemRoot%\\system32\\Wmmvsvc.dll" fullword ascii
		$s4 = "%SystemRoot%\\system32\\scardprv.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="e8cd12071a8e823ebc434c8ee3e23203" or 2 of them )
}