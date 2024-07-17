
rule VOLEXITY_Apt_Ico_Uta0040_B64_C2 : UTA0040 FILE
{
	meta:
		description = "Detection of malicious ICO files used in 3CX compromise."
		author = "threatintel@volexity.com"
		id = "1efb6376-a362-5f03-b4d3-08cd7d634de6"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2023/2023-03-30 3CX/indicators/rules.yar#L1-L31"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "2667a36ce151c6e964f9ce9a6f587eedbffdd6ec76e451a23c5cfdd08248d15e"
		score = 75
		quality = 80
		tags = "UTA0040, FILE"
		hash1 = "a541e5fc421c358e0a2b07bf4771e897fb5a617998aa4876e0e1baa5fbb8e25c"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$IEND_dollar = {49 45 4e 44 ae 42 60 82 24}
		$IEND_nodollar = {49 45 4e 44 ae 42 60 82 }

	condition:
		uint16be(0)==0x0000 and filesize <120KB and ($IEND_dollar in ( filesize -500.. filesize ) and not $IEND_nodollar in ( filesize -20.. filesize ) and for any k in (1..#IEND_dollar) : ( for all i in (1..4) : ( uint8(@IEND_dollar[k]+!IEND_dollar[k]+i)<123 and uint8(@IEND_dollar[k]+!IEND_dollar[k]+i)>47)))
}