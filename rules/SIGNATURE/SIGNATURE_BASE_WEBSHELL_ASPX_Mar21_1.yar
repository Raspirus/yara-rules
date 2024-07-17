rule SIGNATURE_BASE_WEBSHELL_ASPX_Mar21_1 : FILE
{
	meta:
		description = "Detects ASPX Web Shells"
		author = "Florian Roth (Nextron Systems)"
		id = "52884135-6b86-5e3e-a866-36a812d5a9af"
		date = "2021-03-12"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-webshells.yar#L9912-L9937"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "acc0d67326d1f764d6fc54681b38f491c55968ec34e40d181426cfcf418eeb21"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "10b6e82125a2ddf3cc31a238e0d0c71a64f902e0d77171766713affede03174d"
		hash2 = "170bee832df176aac0a3c6c7d5aa3fee413b4572030a24c994a97e70f6648ffc"
		hash3 = "31c4d1fc81c052e269866deff324dffb215e7d481a47a2b6357a572a3e685d90"
		hash4 = "41b5c26ac194439612b68e9ec6a638eceaf00842c347ffa551eb009ef6c015a3"
		hash5 = "4b645bc773acde2b3cc204e77ac27c3f6991046c3b75f42d12bc90ec29cff9e3"
		hash6 = "602bb701b78895d4de32f5e78f3c511e5298ba244b29641b11a7c1c483789859"
		hash7 = "7ac47a17c511e25c06a53a1c7a5fbbf05f41f047a4a40b71afa81ce7b59f4b03"
		hash8 = "9a5097d0e8dc29a2814adac070c80fd4b149b33e56aaaf9235af9e87b0501d91"
		hash9 = "9efb5932c0753e45504fc9e8444209b92c2bdf22e63b1c1a44e2d52cb62b4548"
		hash10 = "d40b16307d6434c3281374c0e1bbc0f6db388883e7f6266c3c81de0694266882"

	strings:
		$s1 = ".StartInfo.FileName = 'cmd.exe';" ascii fullword
		$s2 = "<xsl:template match=\"\"/root\"\">" ascii fullword
		$s3 = "<?xml version=\"\"1.0\"\"?><root>test</root>\";" ascii fullword

	condition:
		uint16(0)==0x253c and filesize <6KB and all of them
}