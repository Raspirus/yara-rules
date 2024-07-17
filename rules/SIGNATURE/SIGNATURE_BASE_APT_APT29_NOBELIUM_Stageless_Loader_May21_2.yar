import "pe"

import "math"


rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Stageless_Loader_May21_2 : FILE
{
	meta:
		description = "Detects stageless loader as used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		id = "7b83d327-52fc-5401-ae35-00f6b825678a"
		date = "2021-05-29"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_nobelium_may21.yar#L236-L258"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "850f6a1ad342fd5e4bb29c7bf90a032ddd8ac9d2eac5ffcbedf43e4d04b178f5"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "a4f1f09a2b9bc87de90891da6c0fca28e2f88fd67034648060cef9862af9a3bf"
		hash2 = "c4ff632696ec6e406388e1d42421b3cd3b5f79dcb2df67e2022d961d5f5a9e78"

	strings:
		$x1 = "DLL_stageless.dll" ascii fullword
		$s1 = "c:\\users\\devuser\\documents" ascii fullword nocase
		$s2 = "VisualServiceComponent" ascii fullword
		$s3 = "CheckUpdteFrameJavaCurrentVersion" ascii fullword
		$op1 = { a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 68 d8 d4 00 10 57 a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 }
		$op2 = { ff d6 33 05 00 ?0 0? 10 68 d8 d4 00 10 57 a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 68 e8 d4 00 10 }

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 2 of them or 3 of them
}