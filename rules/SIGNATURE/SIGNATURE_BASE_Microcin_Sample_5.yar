rule SIGNATURE_BASE_Microcin_Sample_5 : FILE
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "cd06f9f7-0ba3-52c9-a814-be1cd53e2e42"
		date = "2017-09-26"
		modified = "2023-12-05"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_microcin.yar#L92-L110"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "18b9b80ad3c27f32c71197f33e5e99742662cf5cf4ed5f83d574d44ba63f8b5f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b9c51397e79d5a5fd37647bc4e4ee63018ac3ab9d050b02190403eb717b1366e"

	strings:
		$x1 = "Sorry, you are not fortuante ^_^, Please try other password dictionary " fullword ascii
		$x2 = "DomCrack <IP> <UserName> <Password_Dic file path> <option>" fullword ascii
		$x3 = "The password is \"%s\"         Time: %d(s)" fullword ascii
		$x4 = "The password is \" %s \"         Time: %d(s)" fullword ascii
		$x5 = "No password found!" fullword ascii
		$x7 = "Can not found the Password Dictoonary file! " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them ) or 2 of them
}