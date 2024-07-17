
rule SIGNATURE_BASE_REDLEAVES_Coreimplant_Uniquestrings : FILE
{
	meta:
		description = "Strings identifying the core REDLEAVES RAT in its deobfuscated state"
		author = "USG"
		id = "fd4d4804-f7d9-549d-8f63-5f409d6180f9"
		date = "2018-12-20"
		modified = "2024-04-17"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_uscert_ta17-1117a.yar#L49-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ce6ab0f4007f3ea3c31442cab702ad3579faa6835d5ee9b4c03516ce0499bf3e"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$unique2 = "RedLeavesSCMDSimulatorMutex" nocase wide ascii
		$unique4 = "red_autumnal_leaves_dllmain.dll" wide ascii
		$unique7 = "\\NamePipe_MoreWindows" wide ascii

	condition:
		not uint32(0)==0x66676572 and any of them
}