rule SIGNATURE_BASE_OSX_Backdoor_Bella : FILE
{
	meta:
		description = "Bella MacOS/OSX backdoor"
		author = "John Lambert @JohnLaTwC"
		id = "d2a994f9-acff-5de4-8f70-453b5d4d7947"
		date = "2018-02-23"
		modified = "2023-12-05"
		reference = "https://twitter.com/JohnLaTwC/status/911998777182924801"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_osx_backdoor_bella.yar#L2-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "4288a81779a492b5b02bad6e90b2fa6212fa5f8ee87cc5ec9286ab523fc02446 cec7be2126d388707907b4f9d681121fd1e3ca9f828c029b02340ab1331a5524 e1cf136be50c4486ae8f5e408af80b90229f3027511b4beed69495a042af95be"
		logic_hash = "c2fa72072decd850698fbaaa9c2a6687cdf64e6bac068ff52a97963053db4339"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$h1 = "#!/usr/bin/env"
		$s0 = "subprocess" fullword ascii
		$s1 = "import sys" fullword ascii
		$s2 = "shutil" fullword ascii
		$p0 = "create_bella_helpers" fullword ascii
		$p1 = "is_there_SUID_shell" fullword ascii
		$p2 = "BELLA IS NOW RUNNING" fullword ascii
		$p3 = "SELECT * FROM bella WHERE id" fullword ascii
		$subpart1_a = "inject_payloads" fullword ascii
		$subpart1_b = "check_if_payloads" fullword ascii
		$subpart1_c = "updateDB" fullword ascii
		$subpart2_a = "appleIDPhishHelp" fullword ascii
		$subpart2_b = "appleIDPhish" fullword ascii
		$subpart2_c = "iTunes" fullword ascii

	condition:
		uint32(0)==0x752f2123 and $h1 at 0 and filesize <120KB and @s0[1]<100 and @s1[1]<100 and @s2[1]<100 and 1 of ($p*) or all of ($subpart1_*) or all of ($subpart2_*)
}