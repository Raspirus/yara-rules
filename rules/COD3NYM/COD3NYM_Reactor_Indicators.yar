
rule COD3NYM_Reactor_Indicators : SUSPICIOUS OBFUSCATION FILE
{
	meta:
		description = "Ezriz .NET Reactor obfuscator"
		author = "Jonathan Peters"
		id = "8dc07bbd-cbeb-5214-a27a-555a0d396197"
		date = "2024-01-09"
		modified = "2024-01-10"
		reference = "https://github.com/cod3nym/detection-rules/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/malcat/obfuscators.yar#L103-L119"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		logic_hash = "40a03eb487e2c02a032c4bfb51580dbb764e0a49ceee5ae92c54a5ee3ede9696"
		score = 65
		quality = 80
		tags = "SUSPICIOUS, OBFUSCATION, FILE"
		name = ".NET Reactor"
		category = "obfuscation"
		reliability = 90

	strings:
		$ = { 33 7B 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 7D 00 }
		$ = { 3C 50 72 69 76 61 74 65 49 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 44 65 74 61 69 6C 73 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
		$ = { 3C 4D 6F 64 75 6C 65 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }

	condition:
		uint16(0)==0x5a4d and 2 of them
}