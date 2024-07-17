
rule DEADBITS_Silenttrinity_Delivery_Document : FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "be8cf8b7-d7f8-587d-b7bd-ad10796cda7c"
		date = "2019-07-19"
		modified = "2019-07-19"
		reference = "https://countercept.com/blog/hunting-for-silenttrinity/"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/SilentTrinity_Delivery.yara#L1-L30"
		license_url = "N/A"
		logic_hash = "1efaa317dd250fa127b134ff8e6e6ac48d1056059256f790925d2315a6865033"
		score = 75
		quality = 80
		tags = "FILE"
		Description = "Attempts to detect SilentTrinity delivery documents"
		Author = "Adam M. Swanda"

	strings:
		$s0 = "VBE7.DLL" fullword ascii
		$s1 = "TargetPivotTable" fullword ascii
		$s2 = "DocumentUserPassword" fullword wide
		$s3 = "DocumentOwnerPassword" fullword wide
		$s4 = "Scripting.FileSystemObject" fullword wide
		$s5 = "MSXML2.ServerXMLHTTP" fullword wide
		$s6 = "Win32_ProcessStartup " fullword ascii
		$s7 = "Step 3: Start looping through all worksheets" fullword ascii
		$s8 = "Step 2: Start looping through all worksheets" fullword ascii
		$s9 = "Stringer" fullword wide
		$s10 = "-decode -f" fullword wide
		$s11 = "2. Da biste pogledali dokument, molimo kliknite \"OMOGU" fullword wide

	condition:
		uint16(0)==0xcfd0 and filesize <200KB and (8 of ($s*) or all of them )
}