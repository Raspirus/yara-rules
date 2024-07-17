
rule SIGNATURE_BASE_Susp_Powershell_Sep17_2 : FILE
{
	meta:
		description = "Detects suspicious PowerShell script in combo with VBS or JS "
		author = "Florian Roth (Nextron Systems)"
		id = "e44d1dfc-0858-5248-a57f-efb5c647f4cc"
		date = "2017-09-30"
		modified = "2024-04-03"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_powershell_susp.yar#L150-L170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0819f57afb6d1d878e4db4079bfd43ccac520829c877de04d16d8bd048a35ab5"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e387f6c7a55b85e0675e3b91e41e5814f5d0ae740b92f26ddabda6d4f69a8ca8"

	strings:
		$x1 = ".Run \"powershell.exe -nop -w hidden -e " ascii
		$x2 = "FileExists(path + \"\\..\\powershell.exe\")" fullword ascii
		$x3 = "window.moveTo -4000, -4000" fullword ascii
		$s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii

	condition:
		filesize <20KB and (( uint16(0)==0x733c and 1 of ($x*)) or 2 of them )
}