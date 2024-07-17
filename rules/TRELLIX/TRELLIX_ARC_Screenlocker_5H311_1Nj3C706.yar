rule TRELLIX_ARC_Screenlocker_5H311_1Nj3C706 : SCREENLOCKER FILE
{
	meta:
		description = "Rule to detect the screenlocker 5h311_1nj3c706"
		author = "Marc Rivero | McAfee ATR Team"
		id = "50bbe8e1-4721-5277-b786-d2a2d9acf917"
		date = "2018-08-07"
		modified = "2020-08-14"
		reference = "https://twitter.com/demonslay335/status/1038060120461266944"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_screenlocker_5h311_1nj3c706.yar#L1-L33"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "016ee638bd4fccd5ca438c2e0abddc4b070f59269c08f11c5313ba9c37190718"
		logic_hash = "61b4495841c77053ba2631f087197719f3ee45cd93add022f23b87ece8563619"
		score = 75
		quality = 70
		tags = "SCREENLOCKER, FILE"
		rule_version = "v1"
		malware_type = "screenlocker"
		malware_family = "ScreenLocker:W32/5h311_1nj3c706"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "C:\\Users\\Hoang Nam\\source\\repos\\WindowsApp22\\WindowsApp22\\obj\\Debug\\WindowsApp22.pdb" fullword ascii
		$s2 = "cmd.exe /cREG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop /v NoChangingWallPaper /t REG_DWOR" wide
		$s3 = "C:\\Users\\file1.txt" fullword wide
		$s4 = "C:\\Users\\file2.txt" fullword wide
		$s5 = "C:\\Users\\file.txt" fullword wide
		$s6 = " /v Wallpaper /t REG_SZ /d %temp%\\IMG.jpg /f" fullword wide
		$s7 = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" fullword wide
		$s8 = "All your file has been locked. You must pay money to have a key." fullword wide
		$s9 = "After we receive Bitcoin from you. We will send key to your email." fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}