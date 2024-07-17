rule SIGNATURE_BASE_Gen_Unicorn_Obfuscated_Powershell : FILE
{
	meta:
		description = "PowerShell payload obfuscated by Unicorn toolkit"
		author = "John Lambert @JohnLaTwC"
		id = "0235795b-6d0b-5bba-8ae6-606c3b613c86"
		date = "2018-04-03"
		modified = "2023-12-05"
		reference = "https://github.com/trustedsec/unicorn/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_unicorn_obfuscated_powershell.yar#L1-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "b93d2fe6a671a6a967f31d5b3a0a16d4f93abcaf25188a2bbdc0894087adb10d"
		logic_hash = "cb0044d5ee146213c96161d52880ce6c20d5884d57620c73f359673d4ae4b76b"
		score = 75
		quality = 85
		tags = "FILE"
		hash2 = "1afb9795cb489abce39f685a420147a2875303a07c32bf7eec398125300a460b"

	strings:
		$h1 = "powershell"
		$sa1 = ".value.toString() 'JAB"
		$sa2 = ".value.toString() ('JAB"
		$sb1 = "-w 1 -C \"s"
		$sb2 = "/w 1 /C \"s"

	condition:
		filesize <20KB and uint32be(0)==0x706f7765 and $h1 at 0 and ( uint16be( filesize -2)==0x2722 or ( uint16be( filesize -2)==0x220a and uint8( filesize -3)==0x27) or ( uint16be( filesize -2)==0x2922 and uint8( filesize -3)==0x27)) and (1 of ($sa*) and 1 of ($sb*))
}