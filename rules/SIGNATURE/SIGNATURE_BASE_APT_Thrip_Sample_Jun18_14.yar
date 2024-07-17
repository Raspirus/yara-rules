rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_14 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "736e2700-cdcb-5165-b786-67edaef765b6"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L256-L276"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c96a40495bc2a17a6215c877ad054bd2e1e10c524c2d54da1955d370b9ccdcd7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "67dd44a8fbf6de94c4589cf08aa5757b785b26e49e29488e9748189e13d90fb3"

	strings:
		$s1 = "%SystemRoot%\\System32\\svchost.exe -k " fullword ascii
		$s2 = "spdirs.dll" fullword ascii
		$s3 = "Provides storm installation services such as Publish, and Remove." fullword ascii
		$s4 = "RegSetValueEx(Svchost\\netsvcs)" fullword ascii
		$s5 = "Load %s Error" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and ((pe.exports("InstallA") and pe.exports("InstallB") and pe.exports("InstallC")) or all of them )
}