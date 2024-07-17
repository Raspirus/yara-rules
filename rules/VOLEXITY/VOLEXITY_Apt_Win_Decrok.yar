rule VOLEXITY_Apt_Win_Decrok : INKYSQUID
{
	meta:
		description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
		author = "threatintel@volexity.com"
		id = "dc83843d-fd2a-52f1-82e8-8e36b135a0c5"
		date = "2021-06-23"
		modified = "2021-09-02"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L47-L67"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
		logic_hash = "47fa03e95ac17ba7195858cd63b1769e5d56ab8a5edf872b345989b767050b87"
		score = 75
		quality = 80
		tags = "INKYSQUID"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}
		$av1 = "Select * From AntiVirusProduct" wide
		$av2 = "root\\SecurityCenter2" wide
		$funcformat = { 25 30 32 78 [0-10] 43 72 65 61 74 65 54 68 72 65 61 64 }

	condition:
		all of them
}