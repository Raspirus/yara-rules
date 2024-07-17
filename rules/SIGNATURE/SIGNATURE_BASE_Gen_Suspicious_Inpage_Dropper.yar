rule SIGNATURE_BASE_Gen_Suspicious_Inpage_Dropper : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Florian Roth"
		id = "9144711a-e6ee-5c97-a5f4-3f6df1d630dc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://twitter.com/Ahmedfshosha/status/1138138981521154049"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_InPage_dropper.yar#L1-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8ab5d0bffa72b32f4c388f42a38a799c178fddf9f06b1262842e146c43448bd4"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "013417bd5465d6362cd43c70015c7a74a1b8979785b842b7cfa543cb85985852"
		hash2 = "1d1e7a6175e6c514aaeca8a43dabefa017ddc5b166ccb636789b6a767181a022"
		hash3 = "bd293bdf3be0a44a92bdb21e5fa75c124ad1afed3c869697bf90c9732af0e994"
		hash4 = "d8edf3e69f006f85b9ee4e23704cd5e95e895eb286f9b749021d090448493b6f"

	strings:
		$s1 = "InPage Arabic Document"
		$c1 = {31 06 83 c6 04 e2 }
		$c2 = {90 90 90 90 90 90 90 e8 fb }

	condition:
		filesize <3MB and uint32be(0)==0xD0CF11E0 and $s1 and 1 of ($c*)
}