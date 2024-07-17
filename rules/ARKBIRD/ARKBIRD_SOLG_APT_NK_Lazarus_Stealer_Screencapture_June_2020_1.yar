rule ARKBIRD_SOLG_APT_NK_Lazarus_Stealer_Screencapture_June_2020_1 : FILE
{
	meta:
		description = "Detect ScreenCapture malware used by Lazarus APT"
		author = "Arkbird_SOLG, James_inthe_box"
		id = "bb0463ac-6219-5a12-b3d2-fc82800bda69"
		date = "2020-06-23"
		modified = "2021-07-13"
		reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-23/APT_Lazarus_Stealer_June_2020_1.yar#L3-L31"
		license_url = "N/A"
		logic_hash = "66f8d3da0f70f6c4ed6f853ab4040d7f96c043e9e194f1720999b48910b3e756"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "6caa98870efd1097ee13ae9c21c6f6c9202a19ad049a9e65c60fce5c889dc4c8"

	strings:
		$s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease\\ScreenCapture_Win32_DllRelease.pdb" fullword ascii
		$s2 = "CloseHandle ScreenCaptureMutex failure! %d" fullword ascii
		$s3 = "ScreenCapture_Win32_DllRelease.dll" fullword ascii
		$s4 = "ScreenCaptureMutex already created! %s\n" fullword ascii
		$s5 = "Capturing screen...\n" fullword ascii
		$s6 = "%s\\P%02d%lu.tmp" fullword ascii
		$s7 = "ScreenCaptureThread finished!" fullword ascii
		$s8 = "ScreenCaptureThread started!" fullword ascii
		$s9 = "ScreenCapture start time set to %llu" fullword ascii
		$s10 = "ScreenCaptureMutex already created! %s\n" fullword ascii
		$s11 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
		$s12 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
		$s13 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
		$s14 = "[END] ScreenCaptureThread terminated!" fullword ascii
		$s15 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 }
		$s16 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 }
		$s17 = "Entered Windows direcotry, skipping..." fullword ascii
		$s18 = "Found %d entries." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <80KB and 14 of them
}