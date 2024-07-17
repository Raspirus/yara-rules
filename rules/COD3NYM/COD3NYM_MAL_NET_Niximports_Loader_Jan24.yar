import "pe"


rule COD3NYM_MAL_NET_Niximports_Loader_Jan24 : FILE
{
	meta:
		description = "Detects open-source NixImports .NET malware loader. A stealthy loader using dynamic import resolving to evade static detection"
		author = "Jonathan Peters"
		id = "f36ad127-4c4b-5b7e-a13c-bfb9d222a438"
		date = "2024-01-12"
		modified = "2024-01-12"
		reference = "https://github.com/dr4k0nia/NixImports/tree/master"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/dotnet/mal/mal_net_niximports_loader.yar#L1-L22"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "dd3f22871879b0bc4990c96d1de957848c7ed0714635bb036c73d8a989fb0b39"
		logic_hash = "e41d7f4cb46aa0baa87d3024e0550efe5058ca49d908bbd34197431c7c054e58"
		score = 80
		quality = 80
		tags = "FILE"

	strings:
		$op1 = { 1F 0A 64 06 1F 11 62 60 }
		$op2 = { 03 20 4D 5A 90 00 94 4B 2A }
		$op3 = { 20 DE 7A 1F F3 20 F7 1B 18 BC }
		$op4 = { 20 CE 1F BE 70 20 DF 1F 3E F8 14 }
		$sa1 = "OffsetToStringData" ascii
		$sa2 = "GetRuntimeMethods" ascii
		$sa3 = "netstandard" ascii

	condition:
		uint16(0)==0x5a4d and all of ($sa*) and 2 of ($op*)
}