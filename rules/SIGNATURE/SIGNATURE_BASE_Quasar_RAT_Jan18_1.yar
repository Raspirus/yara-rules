rule SIGNATURE_BASE_Quasar_RAT_Jan18_1 : FILE
{
	meta:
		description = "Detects Quasar RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "52408897-bfec-5726-9d01-6ff982d50c28"
		date = "2018-01-29"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-vermin-quasar-rat-custom-malware-used-ukraine/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_quasar_vermin.yar#L11-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4b2c8695a053a714e97f3e108f0f359d9e49151297a21e460b3201d8f4e72a89"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0157b43eb3c20928b77f8700ad8eb279a0aa348921df074cd22ebaff01edaae6"
		hash2 = "24956d8edcf2a1fd26805ec58cfd1ee7498e1a59af8cc2f4b832a7ab34948c18"

	strings:
		$a1 = "ping -n 20 localhost > nul" fullword wide
		$s2 = "HandleDownloadAndExecuteCommand" fullword ascii
		$s3 = "DownloadAndExecute" fullword ascii
		$s4 = "UploadAndExecute" fullword ascii
		$s5 = "ShellCommandResponse" fullword ascii
		$s6 = "Select * From Win32_ComputerSystem" fullword wide
		$s7 = "Process could not be started!" fullword wide
		$s8 = ".Core.RemoteShell" ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and $a1 and 3 of them
}