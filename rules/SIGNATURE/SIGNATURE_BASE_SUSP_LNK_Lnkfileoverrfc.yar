
rule SIGNATURE_BASE_SUSP_LNK_Lnkfileoverrfc : FILE
{
	meta:
		description = "Detects APT lnk files that run double extraction and launch routines with autoruns"
		author = "@Grotezinfosec, modified by Florian Roth"
		id = "19c393af-ff7c-5345-a3ef-c06372344baf"
		date = "2018-09-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_lnk_files.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "52ff949a17039c1fa5707ff503aa1a96b3925bdfef01867c9b59a8d72493a84e"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$command = "C:\\Windows\\System32\\cmd.exe" fullword ascii
		$command2 = {2F 00 63 00 20 00 66 00 69 00 6E 00 64 00 73 00 74 00 72}
		$base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii
		$cert = " -decode " ascii

	condition:
		uint16(0)==0x004c and uint32(4)==0x00021401 and filesize >15KB and (2 of them )
}