rule FIREEYE_RT_Trojan_Win64_Generic_22 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "e79661a8-5254-5e8e-b92b-edf1ddb072ff"
		date = "2020-11-26"
		date = "2020-11-26"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/EXCAVATOR/supplemental/yara/Trojan_Win64_Generic_22.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "f7d9961463b5110a3d70ee2e97842ed3"
		logic_hash = "52fbe5c0ee7c05df5fcd62c26caaa5498e32352da9c5940e522aa31d6c808028"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$api1 = "VirtualAllocEx" fullword
		$api2 = "UpdateProcThreadAttribute" fullword
		$api3 = "DuplicateTokenEx" fullword
		$api4 = "CreateProcessAsUserA" fullword
		$inject = { C7 44 24 20 40 00 00 00 33 D2 41 B9 00 30 00 00 41 B8 [4] 48 8B CB FF 15 [4] 48 8B F0 48 85 C0 74 ?? 4C 89 74 24 20 41 B9 [4] 4C 8D 05 [4] 48 8B D6 48 8B CB FF 15 [4] 85 C0 75 [5-10] 4C 8D 0C 3E 48 8D 44 24 ?? 48 89 44 24 30 44 89 74 24 28 4C 89 74 24 20 33 D2 41 B8 [4] 48 8B CB FF 15 }
		$process = { 89 74 24 30 ?? 8D 4C 24 [2] 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 [4] 85 C0 0F 84 [4] 48 8B [2-3] 48 8D 45 ?? 48 89 44 24 50 4C 8D 05 [4] 48 8D 45 ?? 48 89 7D 08 48 89 44 24 48 45 33 C9 ?? 89 74 24 40 33 D2 ?? 89 74 24 38 C7 44 24 30 04 00 08 00 [0-1] 89 74 24 28 ?? 89 74 24 20 FF 15 }
		$token = { FF 15 [4] 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 0F 84 [4] 48 8B 4C 24 ?? 48 8D [2-3] 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 [4] 85 C0 0F 84 [4] 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 01 FF 15 }

	condition:
		(( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B)) and all of them
}