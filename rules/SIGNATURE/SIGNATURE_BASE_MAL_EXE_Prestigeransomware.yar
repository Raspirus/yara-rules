import "pe"


import "pe"


rule SIGNATURE_BASE_MAL_EXE_Prestigeransomware : FILE
{
	meta:
		description = "Detection for Prestige Ransomware"
		author = "Silas Cutler, modfied by Florian Roth"
		id = "5ac8033a-8b15-5abe-89d5-018a4fef9ab5"
		date = "2023-01-04"
		modified = "2023-01-06"
		reference = "https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_100days_of_yara_2023.yar#L171-L195"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57"
		logic_hash = "2f51ca71d28c8d0df8de22011e16919672d5f9d3f3d94594c5d0cbf7f1585a1e"
		score = 80
		quality = 85
		tags = "FILE"
		version = "1.0"
		DaysofYARA = "4/100"

	strings:
		$x_ransom_email = "Prestige.ranusomeware@Proton.me" wide
		$x_reg_ransom_note = "C:\\Windows\\System32\\reg.exe add HKCR\\enc\\shell\\open\\command /ve /t REG_SZ /d \"C:\\Windows\\Notepad.exe C:\\Users\\Public\\README\" /f" wide
		$ransom_message01 = "To decrypt all the data, you will need to purchase our decryption software." wide
		$ransom_message02 = "Contact us {}. In the letter, type your ID = {:X}." wide
		$ransom_message03 = "- Do not try to decrypt your data using third party software, it may cause permanent data loss." wide
		$ransom_message04 = "- Do not modify or rename encrypted files. You will lose them." wide

	condition:
		uint16(0)==0x5A4D and (1 of ($x*) or 2 of them or pe.imphash()=="a32bbc5df4195de63ea06feb46cd6b55")
}