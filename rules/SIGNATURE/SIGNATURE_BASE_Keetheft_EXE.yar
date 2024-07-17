rule SIGNATURE_BASE_Keetheft_EXE : FILE
{
	meta:
		description = "Detects component of KeeTheft - KeePass dump tool - file KeeTheft.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "65531239-c5fa-5285-8f44-2d858e211c9b"
		date = "2017-08-29"
		modified = "2023-12-05"
		reference = "https://github.com/HarmJ0y/KeeThief"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L3993-L4012"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a6019248ad9708b1508fdf77a2ecbe92a7e8aac916fbca88aec117abeb07b9a0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f06789c3e9fe93c165889799608e59dda6b10331b931601c2b5ae06ede41dc22"

	strings:
		$x1 = "Error: Could not create a thread for the shellcode" fullword wide
		$x2 = "Could not find address marker in shellcode" fullword wide
		$x3 = "GenerateDecryptionShellCode" fullword ascii
		$x4 = "KeePassLib.Keys.KcpPassword" fullword wide
		$x5 = "************ Found a CompositeKey! **********" fullword wide
		$x6 = "*** Interesting... there are multiple .NET runtimes loaded in KeePass" fullword wide
		$x7 = "GetKcpPasswordInfo" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}