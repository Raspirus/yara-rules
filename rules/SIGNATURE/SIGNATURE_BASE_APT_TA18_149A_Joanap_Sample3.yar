import "pe"


rule SIGNATURE_BASE_APT_TA18_149A_Joanap_Sample3 : FILE
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		author = "Florian Roth (Nextron Systems)"
		id = "1c2551bc-01dd-5b30-a4cc-703a868cde73"
		date = "2018-05-30"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta18_149A.yar#L57-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a3da6c70d2ab94820324a55f1bcdcf5507a8ddf26efc80904daf0d9b27ac9312"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a1c483b0ee740291b91b11e18dd05f0a460127acfc19d47b446d11cd0e26d717"

	strings:
		$s1 = "mssvcdll.dll" fullword ascii
		$s2 = "https://www.google.com/index.html" fullword ascii
		$s3 = "LOGINDLG" fullword wide
		$s4 = "rundll" fullword ascii
		$s5 = "%%s\\%%s%%0%dd.%%s" fullword ascii
		$s6 = "%%s\\%%s%%0%dd" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="f6f7b2e00921129d18061822197111cd" or 3 of them )
}