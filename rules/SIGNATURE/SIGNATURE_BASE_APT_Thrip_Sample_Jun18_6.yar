import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_6 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "a1c65bc1-371e-509f-a01c-2d58c1773f95"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L103-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f6cc84ebed26a0dbecfcb3ffb3a11c111ae3d5b40497d59ada518d33bee57fdd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "44f58496578e55623713c4290abb256d03103e78e99939daeec059776bd79ee2"

	strings:
		$s1 = "C:\\Windows\\system32\\Instell.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 1 of them
}