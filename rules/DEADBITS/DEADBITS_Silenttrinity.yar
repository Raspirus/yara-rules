
rule DEADBITS_Silenttrinity : FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "40f9174c-e9a5-5453-b5fa-6c01c46daffa"
		date = "2019-07-19"
		modified = "2019-07-19"
		reference = "https://countercept.com/blog/hunting-for-silenttrinity/"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/SilentTrinity_Payload.yara#L1-L55"
		license_url = "N/A"
		logic_hash = "7fd1775aadfccfdf141c0721f557e6c54b058ac17a59a8e4561dd62ab4a1eff3"
		score = 75
		quality = 78
		tags = "FILE"
		Description = "Attempts to detect the SilentTrinity malware family"
		Author = "Adam M. Swanda"

	strings:
		$pdb01 = "SILENTTRINITY.pdb" ascii
		$str01 = "Found {0} in zip" ascii fullword
		$str02 = "{0} not in zip file" ascii fullword
		$str03 = "Invalid HMAC: {0}" ascii fullword
		$str04 = "Attempting HTTP GET to {0}" ascii fullword
		$str05 = "Downloaded {0} bytes" ascii fullword
		$str06 = "Error downloading {0}: {1}" ascii fullword
		$str07 = "Attempting HTTP POST to {0}" ascii fullword
		$str08 = "POST" ascii fullword
		$str09 = "application/octet-stream" ascii fullword
		$str10 = "Error sending job results to {0}: {1}" ascii fullword
		$str11 = ".dll" ascii fullword
		$str12 = "Trying to resolve assemblies by staging zip" ascii fullword
		$str13 = "'{0}' loaded" ascii fullword
		$str14 = "Usage: SILENTTRINITY.exe <URL> [<STAGE_URL>]" ascii fullword
		$str15 = "IronPython.dll" ascii fullword
		$str16 = "IronPythonDLL" ascii fullword
		$str17 = "DEBUG" ascii fullword
		$str18 = "Main.py" ascii fullword
		$str19 = "Execute" ascii fullword
		$str20 = "SILENTTRINITY.Properties.Resources" ascii fullword
		$str21 = ".zip" ascii fullword
		$a00 = "HttpGet" ascii fullword
		$a01 = "System.Net" ascii fullword
		$a02 = "Target" ascii fullword
		$a03 = "WebClient" ascii fullword
		$a04 = "get_Current" ascii fullword
		$a05 = "Endpoint" ascii fullword
		$a06 = "AesDecrypt" ascii fullword
		$a07 = "AesEncrypt" ascii fullword
		$a08 = "cert" ascii fullword
		$a09 = "WebRequest" ascii fullword
		$a10 = "HttpPost" ascii fullword

	condition:
		uint16(0)==0x5a4d and ((8 of ($str*) or ( all of ($a*) and $pdb01) or $pdb01))
}