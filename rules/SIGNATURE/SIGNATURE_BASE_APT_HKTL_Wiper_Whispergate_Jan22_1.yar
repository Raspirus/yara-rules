rule SIGNATURE_BASE_APT_HKTL_Wiper_Whispergate_Jan22_1 : FILE
{
	meta:
		description = "Detects unknown wiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f04b619e-1df2-5c51-9cab-4a0fffd1c042"
		date = "2022-01-16"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ua_wiper_whispergate.yar#L2-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "72eb50a70b3f2fbb232134ef4706dbb15bdb5893fe06d899bff3b7aacdfadd30"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"

	strings:
		$xc1 = { 41 41 41 41 41 00 59 6F 75 72 20 68 61 72 64 20
               64 72 69 76 65 20 68 61 73 20 62 65 65 6E 20 63
               6F 72 72 75 70 74 65 64 }
		$op1 = { 89 34 24 e8 3f ff ff ff 50 8d 65 f4 31 c0 59 5e 5f }
		$op2 = { 8d bd e8 df ff ff e8 04 de ff ff b9 00 08 00 00 f3 a5 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 00 00 00 00 }
		$op3 = { c7 44 24 0c 00 00 00 00 c7 44 24 08 00 02 00 00 89 44 24 04 e8 aa fe ff ff 83 ec 14 89 34 24 e8 3f ff ff ff 50 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 2 of them ) or all of them
}