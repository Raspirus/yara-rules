rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Nativezone_Loader_May21_1 : FILE
{
	meta:
		description = "Detects NativeZone loader as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		id = "02d9257d-f439-5071-96b0-a973b088e329"
		date = "2021-05-27"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_nobelium_may21.yar#L166-L186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a02fd6fcd7423781bbd2e4458bd61d28e16a5b1a73b1682e63db5c86d53c7da4"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "136f4083b67bc8dc999eb15bb83042aeb01791fc0b20b5683af6b4ddcf0bbc7d"

	strings:
		$s1 = "\\SystemCertificates\\Lib\\CertPKIProvider.dll" ascii
		$s2 = "rundll32.exe %s %s" ascii fullword
		$s3 = "eglGetConfigs" ascii fullword
		$op1 = { 80 3d 74 8c 01 10 00 0f 85 96 00 00 00 33 c0 40 b9 6c 8c 01 10 87 01 33 db 89 5d fc }
		$op2 = { 8b 46 18 e9 30 ff ff ff 90 87 2f 00 10 90 2f 00 10 }
		$op3 = { e8 14 dd ff ff 8b f1 80 3d 74 8c 01 10 00 0f 85 96 00 00 00 33 c0 40 b9 6c 8c 01 10 87 01 }

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 3 of them or 4 of them
}