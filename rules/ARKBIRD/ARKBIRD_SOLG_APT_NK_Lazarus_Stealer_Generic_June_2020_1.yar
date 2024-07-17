import "pe"


rule ARKBIRD_SOLG_APT_NK_Lazarus_Stealer_Generic_June_2020_1 : FILE
{
	meta:
		description = "Detect stealers used by Lazarus APT by common strings"
		author = "Arkbird_SOLG, James_inthe_box"
		id = "11a7c531-91a4-524e-aa5d-c11538f7db58"
		date = "2020-06-23"
		modified = "2021-07-13"
		reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-23/APT_Lazarus_Stealer_June_2020_1.yar#L60-L85"
		license_url = "N/A"
		logic_hash = "878e4a128b7de45f4940e7adccfeb376ce46e87b35b25e162f668303e9fd7852"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "6d461bf3e3ca68b2d6d850322b79d5e3e647b0d515cb10449935bf6d77d7d5f2"
		hash2 = "6caa98870efd1097ee13ae9c21c6f6c9202a19ad049a9e65c60fce5c889dc4c8"

	strings:
		$s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease" fullword ascii
		$s2 = "Mutex failure! %d" fullword ascii
		$s3 = "Win32_DllRelease.dll" fullword ascii
		$s4 = "Mutex already created! %s\n" fullword ascii
		$s5 = "[END]" fullword ascii
		$s6 = "Thread finished!" fullword ascii
		$s7 = "Thread started!" fullword ascii
		$s8 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
		$s9 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
		$s10 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
		$s11 = "Thread terminated!" fullword ascii
		$s12 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 }
		$s13 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 }
		$s14 = "Entered Windows direcotry, skipping..." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <80KB and 11 of them
}