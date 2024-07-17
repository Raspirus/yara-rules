rule SIGNATURE_BASE_APT_UNC2447_PS1_WARPRISM_May21_1 : FILE
{
	meta:
		description = "Detects WARPRISM PowerShell samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "fa389a45-3b31-5a84-9882-49fd6ee8cac5"
		date = "2021-05-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc2447_sombrat.yar#L101-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "09abac2be0f12d31dabfdae9e8a148a28887a2a5df003c7bcb56ba45f1c6a62c"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3090bff3d16b0b150444c3bfb196229ba0ab0b6b826fa306803de0192beddb80"
		hash2 = "63ba6db8c81c60dd9f1a0c7c4a4c51e2e56883f063509ed7b543ad7651fd8806"
		hash3 = "b41a303a4caa71fa260dd601a796033d8bfebcaa6bd9dfd7ad956fac5229a735"

	strings:
		$x1 = "if ($MyInvocation.MyCommand.Path -match '\\S') {" ascii fullword
		$s1 = "[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr " ascii wide
		$s2 = "[Runtime.InteropServices.Marshal]::Copy($" ascii wide
		$s3 = "[System.Diagnostics.Process]::Start((-join(" ascii wide

	condition:
		filesize <5000KB and 1 of ($x*) or 2 of them
}