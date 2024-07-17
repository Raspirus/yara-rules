import "pe"


rule VOLEXITY_Trojan_Win_Pngexe : XEGROUP FILE
{
	meta:
		description = "Detects PNGEXE, a simple reverse shell loader."
		author = "threatintel@volexity.com"
		id = "a0168176-6b2d-56ba-baaa-f011d9f5e3ad"
		date = "2020-09-04"
		modified = "2021-12-07"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-12-06 - XEGroup/indicators/yara.yar#L132-L159"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "72f7d4d3b9d2e406fa781176bd93e8deee0fb1598b67587e1928455b66b73911"
		logic_hash = "05ab554eaf208ff0f5fde37b835c92e55bf0de21bd2700fdd31d81ba338cbdc7"
		score = 75
		quality = 80
		tags = "XEGROUP, FILE"
		hash2 = "4d913ecb91bf32fd828d2153342f5462ae6b84c1a5f256107efc88747f7ba16c"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$a1 = "amd64.png" ascii
		$a2 = "x86.png" ascii

	condition:
		uint16(0)==0x5A4D and (( any of ($a*) and filesize >30KB and filesize <200KB) or pe.imphash()=="ca41f83b03cf3bb51082dbd72e3ba1ba" or pe.imphash()=="e93abc400902e72707edef1f717805f0" or pe.imphash()=="83a5d4aa20a8aca2a9aa6fc2a0aa30b0")
}