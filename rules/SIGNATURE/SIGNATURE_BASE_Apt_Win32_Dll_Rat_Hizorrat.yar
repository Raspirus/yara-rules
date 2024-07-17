rule SIGNATURE_BASE_Apt_Win32_Dll_Rat_Hizorrat : FILE
{
	meta:
		description = "Detects hiZor RAT"
		author = "Florian Roth"
		id = "06fd02f2-2630-5aac-8011-67d67ff42c3f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hizor_rat.yar#L1-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4e3224d34db788d2cba9da74690bf75429d6e8a516d7666d0331e465d08640cb"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "75d3d1f23628122a64a2f1b7ef33f5cf"
		hash2 = "d9821468315ccd3b9ea03161566ef18e"
		hash3 = "b9af5f5fd434a65d7aa1b55f5441c90a"

	strings:
		$s1 = { c7 [5] 40 00 62 00 c7 [5] 77 00 64 00 c7 [5] 61 00 61 00 c7 [5] 6c 00 }
		$s2 = { 66 [7] 0d 40 83 ?? ?? 7c ?? }
		$s3 = { 80 [2] 2e 40 3b ?? 72 ?? }
		$s4 = "CmdProcessExited" wide ascii
		$s5 = "rootDir" wide ascii
		$s6 = "DllRegisterServer" wide ascii
		$s7 = "GetNativeSystemInfo" wide ascii
		$s8 = "%08x%08x%08x%08x" wide ascii

	condition:
		( uint16(0)==0x5A4D or uint32(0)==0x464c457f) and ( all of them )
}