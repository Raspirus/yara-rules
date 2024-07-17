rule ARKBIRD_SOLG_APT_NK_Lazarus_Stealer_Keylog_June_2020_1 : FILE
{
	meta:
		description = "Detect keylog malware used by Lazarus APT"
		author = "Arkbird_SOLG, James_inthe_box"
		id = "dd6aae8c-76d1-514d-905e-21472eb9b9b2"
		date = "2020-06-23"
		modified = "2021-07-13"
		reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-23/APT_Lazarus_Stealer_June_2020_1.yar#L33-L58"
		license_url = "N/A"
		logic_hash = "9a4e17903ad2a7c80651aa8f3d57876d1621be06ba7a683135b11929b232b2fa"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "6d461bf3e3ca68b2d6d850322b79d5e3e647b0d515cb10449935bf6d77d7d5f2"

	strings:
		$s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease\\KeyLog_Win32_DllRelease.pdb" fullword ascii
		$s2 = "CloseHandle KeyLogMutex failure! %d" fullword ascii
		$s3 = "KeyLog_Win32_DllRelease.dll" fullword ascii
		$s4 = "Key Log Mutex already created! %s\n" fullword ascii
		$s5 = "Unable to GetProcAddress of GetAsyncKeyState" fullword ascii
		$s6 = "KeyLogThread finished!" fullword ascii
		$s7 = "KeyLogThread started!" fullword ascii
		$s8 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
		$s9 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
		$s10 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
		$s11 = "[END] KeyLogThread terminated!" fullword ascii
		$s12 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 }
		$s13 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 }
		$s14 = "Entered Windows direcotry, skipping..." fullword ascii
		$s15 = "Found %d entries." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <80KB and 11 of them
}