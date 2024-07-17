rule TRELLIX_ARC_Lg_Utility_Lateral_Movement_Softcell : UTILITY FILE
{
	meta:
		description = "Rule to detect the utility LG from Joeware to do Lateral Movement in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "4f435348-427a-5f35-9545-5582033eb043"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_Operation_SoftCell.yar#L108-L143"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "f88781b9632cd31bb9e3d68730c63c3fcd0ebe4a09b70b5b54d456cdc9ae8d01"
		score = 75
		quality = 70
		tags = "UTILITY, FILE"
		rule_version = "v1"
		malware_type = "utility"
		malware_family = "Utility:W32/Joeware"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "lg \\\\comp1\\users louise -add -r comp3" fullword ascii
		$s2 = "lg \\\\comp1\\users S-1-5-567-678-89765-456 -sid -add" fullword ascii
		$s3 = "lg \\\\comp1\\users -sidsout" fullword ascii
		$s4 = "Enumerates members of localgroup users on localhost" fullword ascii
		$s5 = "Adds SID resolved at comp3 for louise to localgroup users on comp1" fullword ascii
		$s6 = "CodeGear C++ - Copyright 2008 Embarcadero Technologies" fullword ascii
		$s7 = "Lists members of localgroup users on comp1 in SID format" fullword ascii
		$s8 = "ERROR: Verify that CSV lines are available in PIPE input. " fullword ascii
		$op0 = { 89 43 24 c6 85 6f ff ff ff 00 83 7b 24 10 72 05 }
		$op1 = { 68 f8 0e 43 00 e8 8d ff ff ff 83 c4 20 68 f8 0e }
		$op2 = { 66 c7 85 74 ff ff ff 0c 00 8d 55 d8 52 e8 e9 eb }

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="327ce3f883a5b59e966b5d0e3a321156" and all of them )
}