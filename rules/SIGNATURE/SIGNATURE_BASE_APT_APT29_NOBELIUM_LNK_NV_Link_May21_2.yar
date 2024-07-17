import "pe"

import "math"


rule SIGNATURE_BASE_APT_APT29_NOBELIUM_LNK_NV_Link_May21_2 : FILE
{
	meta:
		description = "Detects NV Link as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		id = "52c2caf9-13df-5614-9c9e-afcd76ec77f9"
		date = "2021-05-29"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_nobelium_may21.yar#L85-L97"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5eee9df368da3fc98c00a0f8c65a7f3bd5b812342082be58054b272b5bb03455"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "RegisterOCX BOOM" ascii wide
		$s2 = "cmd.exe /c start BOOM.exe" ascii wide

	condition:
		filesize <5000KB and 1 of them
}