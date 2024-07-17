
rule SIGNATURE_BASE_Triton_Trilog : FILE
{
	meta:
		description = "Detects Triton APT malware - file trilog.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ae2c9b47-2a67-50c6-9d2a-dc47b4fa69ef"
		date = "2017-12-14"
		modified = "2023-12-05"
		reference = "https://goo.gl/vtQoCQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_triton.yar#L70-L85"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6406e9e7651978a6817079945dc801afdb6c16dd107527cbfd9a946eca27a51a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230"

	strings:
		$s1 = "inject.bin" ascii
		$s2 = "PYTHON27.DLL" fullword ascii
		$s3 = "payload" ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}