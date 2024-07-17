
rule VOLEXITY_Apt_Win_Powerstar : CHARMINGKITTEN
{
	meta:
		description = "Custom PowerShell backdoor used by Charming Kitten."
		author = "threatintel@volexity.com"
		id = "febcd23b-6545-571b-905d-18dffe8e913f"
		date = "2021-10-13"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L122-L150"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "2cbf59eaee60a8f84b1ac35cec3b01592a2a0f56c92a2db218bb26a15be24bf3"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		hash1 = "de99c4fa14d99af791826a170b57a70b8265fee61c6b6278d3fe0aad98e85460"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$appname = "[AppProject.Program]::Main()" ascii wide
		$langfilters1 = "*shar*" ascii wide
		$langfilters2 = "*owers*" ascii wide
		$definitions1 = "[string]$language" ascii wide
		$definitions2 = "[string]$Command" ascii wide
		$definitions3 = "[string]$ThreadName" ascii wide
		$definitions4 = "[string]$StartStop" ascii wide
		$sess = "$session = $v + \";;\" + $env:COMPUTERNAME + $mac;" ascii wide

	condition:
		$appname or all of ($langfilters*) or all of ($definitions*) or $sess
}