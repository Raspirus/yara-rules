rule VOLEXITY_Trojan_Win_Backwash_Iis : XEGROUP
{
	meta:
		description = "Variant of the BACKWASH malware family with IIS worm functionality."
		author = "threatintel@volexity.com"
		id = "08a86a58-32af-5c82-90d2-d6603dae8d63"
		date = "2020-09-04"
		modified = "2021-12-07"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-12-06 - XEGroup/indicators/yara.yar#L161-L184"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "98e39573a3d355d7fdf3439d9418fdbf4e42c2e03051b5313d5c84f3df485627"
		logic_hash = "95a7f9e0afb031b49cd0da66b5a887d26ad2e06cce625bc45739b4a80e96ce9c"
		score = 75
		quality = 80
		tags = "XEGROUP"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$a1 = "GetShell" ascii
		$a2 = "smallShell" ascii
		$a3 = "createSmallShell" ascii
		$a4 = "getSites" ascii
		$a5 = "getFiles " ascii
		$b1 = "action=saveshell&domain=" ascii wide
		$b2 = "&shell=backsession.aspx" ascii wide

	condition:
		all of ($a*) or any of ($b*)
}