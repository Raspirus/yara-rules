rule SIGNATURE_BASE_APT_APT29_NOBELIUM_JS_Envyscout_May21_1 : FILE
{
	meta:
		description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		id = "42739aad-a88a-545b-8256-1f727c79c4f8"
		date = "2021-05-29"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_nobelium_may21.yar#L56-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ad8a7bb5a1d2065e3a573842fb37ee3c63b7695c18840f0c26d32e6ae3d99c6c"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "[i].charCodeAt(0) ^ 2);}"

	condition:
		filesize <5000KB and 1 of them
}