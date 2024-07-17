rule COD3NYM_MAL_NET_Limecrypter_Runpe_Jan24 : FILE
{
	meta:
		description = "Detects LimeCrypter RunPE module. LimeCrypter is an open source .NET based crypter and loader commonly used by threat actors"
		author = "Jonathan Peters"
		id = "06ecd638-0102-5762-b363-fdc390dda04b"
		date = "2024-01-16"
		modified = "2024-01-16"
		reference = "https://github.com/NYAN-x-CAT/Lime-Crypter/tree/master"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/dotnet/mal/mal_net_limecrypter_runpe.yar#L1-L22"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "bcc8c679acfc3aabf22ebdb2349b1fabd351a89fd23a716d85154049d352dd12"
		logic_hash = "b01a68c60d62cf94ef16340316acb9b96d1e671c372559b86a8e6a5d8e80f7d9"
		score = 80
		quality = 80
		tags = "FILE"

	strings:
		$op1 = { 1F 1A 58 1F 1A 58 28 }
		$op2 = { 20 B3 00 00 00 8D ?? 00 00 01 13 ?? 11 ?? 16 20 02 00 01 00 }
		$op3 = { 11 0? 11 0? 20 00 30 00 00 1F 40 28 ?? 00 00 06 }
		$op4 = { 6E 20 FF 7F 00 00 6A FE 02 }
		$s1 = "RawSecurityDescriptor" ascii
		$s2 = "CommonAce" ascii

	condition:
		uint16(0)==0x5a4d and all of ($s*) and 2 of ($op*)
}