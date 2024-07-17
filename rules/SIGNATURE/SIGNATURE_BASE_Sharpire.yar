rule SIGNATURE_BASE_Sharpire : FILE
{
	meta:
		description = "Auto-generated rule - file Sharpire.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "747f2798-4f93-5073-b358-969060a1c937"
		date = "2017-09-23"
		modified = "2022-12-21"
		reference = "https://github.com/0xbadjuju/Sharpire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4038-L4061"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1437b4c5229761bcc18d97ea6328866f4b9c763461fa6ecb5c18e6f3961c3114"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "327a1dc2876cd9d7f6a5b3777373087296fc809d466e42861adcf09986c6e587"

	strings:
		$x1 = "\\obj\\Debug\\Sharpire.pdb" ascii
		$x2 = "[*] Upload of $fileName successful" fullword wide
		$s1 = "no shell command supplied" fullword wide
		$s2 = "/login/process.php" fullword wide
		$s3 = "invokeShellCommand" fullword ascii
		$s4 = "..Command execution completed." fullword wide
		$s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword wide
		$s6 = "/admin/get.php" fullword wide
		$s7 = "[!] Error in stopping job: " fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) and 3 of them ))
}