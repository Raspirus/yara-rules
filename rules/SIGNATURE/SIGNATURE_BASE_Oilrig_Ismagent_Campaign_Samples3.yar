rule SIGNATURE_BASE_Oilrig_Ismagent_Campaign_Samples3 : FILE
{
	meta:
		description = "Detects OilRig malware from Unit 42 report in October 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "e26510bd-d183-566a-a185-ebed7a81401c"
		date = "2017-10-18"
		modified = "2023-12-05"
		reference = "https://goo.gl/JQVfFP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_oct17.yar#L84-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a4984cf33e7b0e0dae264ed11caae6cfab9db2a6047a46ec41c28b5637b4589b"
		score = 75
		quality = 81
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a9f1375da973b229eb649dc3c07484ae7513032b79665efe78c0e55a6e716821"

	strings:
		$x1 = "cmd /c schtasks /query /tn TimeUpdate > NUL 2>&1" ascii
		$x2 = "schtasks /create /sc minute /mo 0002 /tn TimeUpdate /tr" fullword ascii
		$x3 = "-c  SampleDomain.com -m scheduleminutes" fullword ascii
		$x4 = ".ntpupdateserver.com" fullword ascii
		$x5 = ".msoffice365update.com" fullword ascii
		$s1 = "out.exe" fullword ascii
		$s2 = "\\Win32Project1\\Release\\Win32Project1.pdb" ascii
		$s3 = "C:\\windows\\system32\\cmd.exe /c (" ascii
		$s4 = "Content-Disposition: form-data; name=\"file\"; filename=\"a.a\"" fullword ascii
		$s5 = "Agent configured successfully" fullword ascii
		$s6 = "\\runlog*" ascii
		$s7 = "can not specify username!!" fullword ascii
		$s8 = "Agent can not be configured" fullword ascii
		$s9 = "%08lX%04hX%04hX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" fullword ascii
		$s10 = "!!! can not create output file !!!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (pe.imphash()=="538805ecd776b9a42e71aebf94fde1b1" or pe.imphash()=="861ac226fbe8c99a2c43ff451e95da97" or (1 of ($x*) or 3 of them ))
}