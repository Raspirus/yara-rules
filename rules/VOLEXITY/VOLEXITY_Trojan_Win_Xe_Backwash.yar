rule VOLEXITY_Trojan_Win_Xe_Backwash : XEGROUP FILE
{
	meta:
		description = "The BACKWASH malware family, which acts as a reverse shell on the victim machine."
		author = "threatintel@volexity.com"
		id = "93bbbf58-8ba2-565f-98f5-51d6f1a1ab06"
		date = "2020-09-04"
		modified = "2021-12-07"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-12-06 - XEGroup/indicators/yara.yar#L99-L129"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "815d262d38a26d5695606d03d5a1a49b9c00915ead1d8a2c04eb47846100e93f"
		logic_hash = "cabe7d17017c95943b7ae9d1827b3a5cb8ed3b02506222367498a73fec8d0914"
		score = 75
		quality = 80
		tags = "XEGROUP, FILE"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$pdb1 = "x:\\MultiOS_ReverseShell-master\\Multi-OS_ReverseShell\\obj\\Release\\XEReverseShell.pdb"
		$pdb2 = "\\Release\\XEReverseShell.pdb"
		$a1 = "RunServer" ascii
		$a2 = "writeShell" ascii
		$a3 = "GetIP" ascii
		$b1 = "xequit" wide
		$b2 = "setshell" wide

	condition:
		any of ($pdb*) or (( all of ($a*) or all of ($b*)) and filesize <40KB)
}