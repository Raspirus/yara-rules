
rule VOLEXITY_Apt_Win_Rokload : INKYSQUID
{
	meta:
		description = "A shellcode loader used to decrypt and run an embedded executable."
		author = "threatintel@volexity.com"
		id = "229dbf3c-1538-5ecd-b5f8-8c9a9c81c515"
		date = "2021-06-23"
		modified = "2021-09-02"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L69-L83"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "85cd5c3bb028fe6931130ccd5d0b0c535c01ce2bcda660a3b72581a1a5382904"
		logic_hash = "8d65d32fd5bc055ca0e3831d3db88299e7c99f8547a170d3c53ec2c4001496a3"
		score = 75
		quality = 80
		tags = "INKYSQUID"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$bytes00 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 57 41 54 41 55 41 56 41 57 48 ?? ?? ?? b9 ?? ?? ?? ?? 33 ff e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 4c 8b e8 e8 ?? ?? ?? ?? 4c 8b f0 41 ff d6 b9 ?? ?? ?? ?? 44 8b f8 e8 ?? ?? ?? ?? 4c 8b e0 e8 ?? ?? ?? ?? 48 }

	condition:
		$bytes00 at 0
}