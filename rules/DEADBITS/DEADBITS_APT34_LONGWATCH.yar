
rule DEADBITS_APT34_LONGWATCH : APT34 WINMALWARE KEYLOGGER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "74a6a408-2f0e-567d-8968-c304d258df81"
		date = "2019-07-22"
		modified = "2019-07-22"
		reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/APT34_LONGWATCH.yara#L1-L43"
		license_url = "N/A"
		logic_hash = "8f9ed228325800baea3a2874c71337709c04d93419d4d56821a791dbce6f4582"
		score = 75
		quality = 78
		tags = "APT34, WINMALWARE, KEYLOGGER, FILE"
		Description = "APT34 Keylogger"

	strings:
		$log = "c:\\windows\\temp\\log.txt" ascii fullword
		$clipboard = "---------------CLIPBOARD------------" ascii fullword
		$func0 = "\"Main Invoked.\"" ascii fullword
		$func1 = "\"Main Returned.\"" ascii fullword
		$logger3 = ">---------------------------------------------------" ascii fullword
		$logger4 = "[ENTER]" ascii fullword
		$logger5 = "[CapsLock]" ascii fullword
		$logger6 = "[CRTL]" ascii fullword
		$logger7 = "[PAGE_UP]" ascii fullword
		$logger8 = "[PAGE_DOWN]" ascii fullword
		$logger9 = "[HOME]" ascii fullword
		$logger10 = "[LEFT]" ascii fullword
		$logger11 = "[RIGHT]" ascii fullword
		$logger12 = "[DOWN]" ascii fullword
		$logger13 = "[PRINT]" ascii fullword
		$logger14 = "[PRINT SCREEN]" ascii fullword
		$logger15 = "[INSERT]" ascii fullword
		$logger16 = "[SLEEP]" ascii fullword
		$logger17 = "[PAUSE]" ascii fullword
		$logger18 = "[TAB]" ascii fullword
		$logger19 = "[ESC]" ascii fullword
		$logger20 = "[DEL]" ascii fullword
		$logger21 = "[ALT]" ascii fullword

	condition:
		uint16(0)==0x5a4d and $log and all of ($func*) and all of ($logger*) and $clipboard
}