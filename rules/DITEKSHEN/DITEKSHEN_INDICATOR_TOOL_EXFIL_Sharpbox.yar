rule DITEKSHEN_INDICATOR_TOOL_EXFIL_Sharpbox : FILE
{
	meta:
		description = "Detect SharpBox, C# tool for compressing, encrypting, and exfiltrating data to Dropbox using the Dropbox API"
		author = "ditekSHen"
		id = "cd834fe2-dc77-509d-a8f9-d631f395bcd8"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1061-L1080"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "b03ab3786b2a2e6774d94be4edf700a7154d8d400c7b2b31c73c68ce9fe0c08a"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "UploadData" fullword ascii
		$s2 = "isAttached" fullword ascii
		$s3 = "DecryptFile" fullword ascii
		$s4 = "set_dbxPath" fullword ascii
		$s5 = "set_dbxToken" fullword ascii
		$s6 = "set_decrypt" fullword ascii
		$s7 = "GeneratePass" fullword ascii
		$s8 = "FileUploadToDropbox" fullword ascii
		$s9 = "\\SharpBox.pdb" ascii
		$s10 = "https://content.dropboxapi.com/2/files/upload" fullword wide
		$s12 = "Dropbox-API-Arg: {\"path\":" wide
		$s13 = "X509Certificate [{0}] Policy Error: '{1}'" fullword wide

	condition:
		uint16(0)==0x5a4d and 7 of them
}