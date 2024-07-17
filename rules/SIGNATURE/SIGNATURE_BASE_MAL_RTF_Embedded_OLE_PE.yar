rule SIGNATURE_BASE_MAL_RTF_Embedded_OLE_PE : FILE
{
	meta:
		description = "Detects a suspicious string often used in PE files in a hex encoded object stream"
		author = "Florian Roth (Nextron Systems)"
		id = "20044f08-9574-5baf-b91e-47613e490d62"
		date = "2018-01-22"
		modified = "2023-11-25"
		reference = "https://www.nextron-systems.com/2018/01/22/creating-yara-rules-detect-embedded-exe-files-ole-objects/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_strings_in_ole.yar#L2-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "054abb34ae84e02469d726809a6d8aa582ebad65dd8385de7800d3f5db7ee31c"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$a1 = "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f6465" ascii
		$a2 = "4b45524e454c33322e646c6c" ascii
		$a3 = "433a5c66616b65706174685c" ascii
		$m3 = "4d5a40000100000006000000ffff"
		$m2 = "4d5a50000200000004000f00ffff"
		$m1 = "4d5a90000300000004000000ffff"

	condition:
		uint32be(0)==0x7B5C7274 and 1 of them
}