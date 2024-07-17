rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_8 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "5eb98c9e-5103-5146-9364-d5f24416406f"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L133-L148"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6c8ddc7fb5f3256e57e66f502f6e3c582d82540f773bf4113cac4a685d45f81b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0f2d09b1ad0694f9e71eeebec5b2d137665375bf1e76cb4ae4d7f20487394ed3"

	strings:
		$x1 = "$.oS.Run('cmd.exe /c '+a+'" fullword ascii
		$x2 = "new $._x('WScript.Shell');" ascii
		$x3 = ".ExpandEnvironmentStrings('%Temp%')+unescape('" ascii

	condition:
		filesize <10KB and 1 of ($x*)
}