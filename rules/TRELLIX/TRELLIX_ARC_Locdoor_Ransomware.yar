
rule TRELLIX_ARC_Locdoor_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect Locdoor/DryCry"
		author = "Marc Rivero | McAfee ATR Team"
		id = "d855d7fd-a1e3-561e-906e-103752285b0f"
		date = "2018-09-02"
		modified = "2020-08-14"
		reference = "https://twitter.com/leotpsc/status/1036180615744376832"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_locdoor.yar#L1-L32"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "0000c55f7cdbbad9bacba0e79637696f3bfeb95a5f71dfa0b398bc77a207eb41"
		logic_hash = "c9519279a929feedae2bab58cd0de91f6c447827fa59afa927726fde84d21e1c"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Locdoor"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "copy \"Locdoor.exe\" \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\temp00000000.exe\"" fullword ascii
		$s2 = "copy wscript.vbs C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\wscript.vbs" fullword ascii
		$s3 = "!! Your computer's important files have been encrypted! Your computer's important files have been encrypted!" fullword ascii
		$s4 = "echo CreateObject(\"SAPI.SpVoice\").Speak \"Your computer's important files have been encrypted! " fullword ascii
		$s5 = "! Your computer's important files have been encrypted! " fullword ascii
		$s7 = "This program is not supported on your operating system." fullword ascii
		$s8 = "echo Your computer's files have been encrypted to Locdoor Ransomware! To make a recovery go to localbitcoins.com and create a wa" ascii
		$s9 = "Please enter the password." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB) and all of them
}