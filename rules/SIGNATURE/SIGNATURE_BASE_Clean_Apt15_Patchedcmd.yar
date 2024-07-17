rule SIGNATURE_BASE_Clean_Apt15_Patchedcmd : FILE
{
	meta:
		description = "This is a patched CMD. This is the CMD that RoyalCli uses."
		author = "Ahmed Zaki"
		id = "c6867ad4-f7f2-5d63-bffd-07599ede635d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt15.yar#L118-L131"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"
		logic_hash = "08a68e14793d2f44ee75e49a43521c7d8bc1fc5ddd005e1fb71cc844966e16ba"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = "eisableCMD" wide
		$ = "%WINDOWS_COPYRIGHT%" wide
		$ = "Cmd.Exe" wide
		$ = "Windows Command Processor" wide

	condition:
		uint16(0)==0x5A4D and all of them
}