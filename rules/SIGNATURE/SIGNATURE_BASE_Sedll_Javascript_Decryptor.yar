
rule SIGNATURE_BASE_Sedll_Javascript_Decryptor : FILE
{
	meta:
		description = "Detects SeDll - DLL is used for decrypting and executing another JavaScript backdoor such as Orz"
		author = "Florian Roth (Nextron Systems)"
		id = "8fafd139-0c4f-5c51-af8f-b4917d2d69b0"
		date = "2017-10-18"
		modified = "2023-01-07"
		reference = "https://goo.gl/MZ7dRg"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_leviathan.yar#L11-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "26ef61d8bb1764dddd951526902fb510fbacc8b808fe99ddee1956dc8b59bd1d"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "146aa9a0ec013aa5bdba9ea9d29f59d48d43bc17c6a20b74bb8c521dbb5bc6f4"

	strings:
		$x1 = "SEDll_Win32.dll" fullword ascii
		$x2 = "regsvr32 /s \"%s\" DR __CIM__" wide
		$s1 = "WScriptW" fullword ascii
		$s2 = "IWScript" fullword ascii
		$s3 = "%s\\%s~%d" fullword wide
		$s4 = "PutBlockToFileWW" fullword ascii
		$s5 = "CheckUpAndDownWW" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and (1 of ($x*) or 4 of them )
}