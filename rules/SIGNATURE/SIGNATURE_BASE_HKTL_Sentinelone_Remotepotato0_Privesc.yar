
rule SIGNATURE_BASE_HKTL_Sentinelone_Remotepotato0_Privesc : FILE
{
	meta:
		description = "Detects RemotePotato0 binary"
		author = "SentinelOne"
		id = "f6dffd6b-e794-5c4a-9700-5c2022168f44"
		date = "2021-04-26"
		modified = "2023-12-05"
		reference = "https://labs.sentinelone.com/relaying-potatoes-dce-rpc-ntlm-relay-eop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_remote_potato0.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f3a3a917908af6260f40b217f966750a095140abb6bf85cf3a728725bc16996f"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$import1 = "CoGetInstanceFromIStorage"
		$istorage_clsid = "{00000306-0000-0000-c000-000000000046}" nocase wide ascii
		$meow_header = { 4d 45 4f 57 }
		$clsid1 = "{11111111-2222-3333-4444-555555555555}" wide ascii
		$clsid2 = "{5167B42F-C111-47A1-ACC4-8EABE61B0B54}" nocase wide ascii

	condition:
		( uint16(0)==0x5A4D) and $import1 and $istorage_clsid and $meow_header and 1 of ($clsid*)
}