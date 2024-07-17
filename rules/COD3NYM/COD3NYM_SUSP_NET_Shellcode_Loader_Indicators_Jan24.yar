
rule COD3NYM_SUSP_NET_Shellcode_Loader_Indicators_Jan24 : FILE
{
	meta:
		description = "Detects indicators of shellcode loaders in .NET binaries"
		author = "Jonathan Peters"
		id = "606a444a-b894-5076-8d5e-1716bbfa588e"
		date = "2024-01-11"
		modified = "2024-01-12"
		reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/dotnet/suspicious_indicators.yar#L1-L22"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "c48752a5b07b58596564f13301276dd5b700bd648a04af2e27d3f78512a06408"
		logic_hash = "28267eb54a4108924df57512bbae9f47f51fd4860b3cf93c014d73b0d4b2dec2"
		score = 65
		quality = 80
		tags = "FILE"

	strings:
		$sa1 = "VirtualProtect" ascii
		$sa2 = "VirtualAlloc" ascii
		$sa3 = "WriteProcessMemory" ascii
		$sa4 = "CreateRemoteThread" ascii
		$sa5 = "CreateThread" ascii
		$sa6 = "WaitForSingleObject" ascii
		$x = "__StaticArrayInitTypeSize=" ascii

	condition:
		uint16(0)==0x5a4d and 3 of ($sa*) and #x==1
}