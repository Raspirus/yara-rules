
rule SIGNATURE_BASE_Vbscript_Favicon_File : FILE
{
	meta:
		description = "VBScript cloaked as Favicon file used in Leviathan incident"
		author = "Florian Roth (Nextron Systems)"
		id = "84147d4e-d062-5ba4-8019-6bf4b72c36c6"
		date = "2017-10-18"
		modified = "2023-01-06"
		reference = "https://goo.gl/MZ7dRg"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_leviathan.yar#L77-L96"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5b89ea916adf6864c8b1cb7cd7ee6d74ea47bf17a0b03cc513046f8d260ae376"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "39c952c7e14b6be5a9cb1be3f05eafa22e1115806e927f4e2dc85d609bc0eb36"

	strings:
		$x1 = "myxml = '<?xml version=\"\"1.0\"\" encoding=\"\"UTF-8\"\"?>';myxml = myxml +'<root>" ascii
		$x2 = ".Run \"taskkill /im mshta.exe" ascii
		$x3 = "<script language=\"VBScript\">Window.ReSizeTo 0, 0 : Window.moveTo -2000,-2000 :" ascii
		$s1 = ".ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") &" ascii
		$s2 = ".ExpandEnvironmentStrings(\"%temp%\") & " ascii

	condition:
		filesize <100KB and ( uint16(0)==0x733c and 1 of ($x*)) or (3 of them )
}