import "pe"

import "math"


rule SIGNATURE_BASE_APT_APT29_NOBELIUM_JS_Envyscout_May21_2 : FILE
{
	meta:
		description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		id = "d5cf3365-fe24-533a-a678-b5b6d4d99997"
		date = "2021-05-29"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_nobelium_may21.yar#L69-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6f5c50b340d628559799897a2ba79add7d126e3ecb2daeb365bc15d64796ccd2"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "saveAs(blob, " ascii
		$s2 = ".iso\");" ascii
		$s3 = "application/x-cd-image" ascii
		$s4 = ".indexOf(\"Win\")!=-1" ascii

	condition:
		filesize <5000KB and all of them
}