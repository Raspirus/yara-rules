rule SBOUSSEADEN_Susp_Msoffice_Addins_Wxll : FILE
{
	meta:
		description = "hunt for suspicious MS Office Addins with code injection capabilities"
		author = "SBousseaden"
		id = "39d3b2af-f848-51c0-a13b-13c0fe3a79dd"
		date = "2020-11-10"
		modified = "2023-03-27"
		reference = "https://twitter.com/JohnLaTwC/status/1315287078855352326"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_susp_msoffice_addins_wxll.yara#L3-L29"
		license_url = "N/A"
		logic_hash = "130a0292b16e934311597d4f91456e6a605477e306a7b1d8171cc4e13794db31"
		score = 65
		quality = 75
		tags = "FILE"

	strings:
		$inj1 = "WriteProcessMemory"
		$inj2 = "NtWriteVirtualMemory"
		$inj3 = "RtlMoveMemory"
		$inj4 = "VirtualAllocEx"
		$inj5 = "NtAllocateVirtualMemory"
		$inj6 = "NtUnmapViewOfSection"
		$inj7 = "VirtualProtect"
		$inj8 = "NtProtectVirtualMemory"
		$inj9 = "SetThreadContext"
		$inj10 = "NtSetContextThread"
		$inj11 = "ResumeThread"
		$inj12 = "NtResumeThread"
		$inj13 = "QueueUserAPC"
		$inj14 = "NtQueueApcThread"
		$inj15 = "NtQueueApcThreadEx"
		$inj16 = "CreateRemoteThread"
		$inj17 = "NtCreateThreadEx"
		$inj18 = "RtlCreateUserThread"

	condition:
		uint16(0)==0x5a4d and (pe.exports("wdAutoOpen") or pe.exports("xlAutoOpen")) and 3 of ($inj*)
}