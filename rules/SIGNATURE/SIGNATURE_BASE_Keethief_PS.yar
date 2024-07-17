rule SIGNATURE_BASE_Keethief_PS : FILE
{
	meta:
		description = "Detects component of KeeTheft - KeePass dump tool - file KeeThief.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "9a54e8d1-3cae-51e8-8da0-024ac25dc6d0"
		date = "2017-08-29"
		modified = "2023-12-05"
		reference = "https://github.com/HarmJ0y/KeeThief"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L3974-L3991"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8d3d4ff3b854c5efad99e6f20121b16d5f2f0a31a4c8efd87a937f857923a5e1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a3b976279ded8e64b548c1d487212b46b03aaec02cb6e199ea620bd04b8de42f"

	strings:
		$x1 = "$WMIProcess = Get-WmiObject win32_process -Filter \"ProcessID = $($KeePassProcess.ID)\"" fullword ascii
		$x2 = "if($KeePassProcess.FileVersion -match '^2\\.') {" fullword ascii

	condition:
		( uint16(0)==0x7223 and filesize <1000KB and (1 of ($x*)))
}