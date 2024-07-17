
rule SIGNATURE_BASE_APT_MAL_Winntilinux_Dropper_Azazelfork_May19 : AZAZEL_FORK FILE
{
	meta:
		description = "Detection of Linux variant of Winnti"
		author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
		id = "d641de9a-e563-5067-b7e4-0aa83a087ed4"
		date = "2019-05-15"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_linux.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
		logic_hash = "0af32675dccfd0ad0c7919683fddced6ad49c65800ffa523773b7342b431379f"
		score = 75
		quality = 85
		tags = "AZAZEL_FORK, FILE"
		version = "1.0"
		TLP = "White"

	strings:
		$config_decr = { 48 89 45 F0 C7 45 EC 08 01 00 00 C7 45 FC 28 00 00 00 EB 31 8B 45 FC 48 63 D0 48 8B 45 F0 48 01 C2 8B 45 FC 48 63 C8 48 8B 45 F0 48 01 C8 0F B6 00 89 C1 8B 45 F8 89 C6 8B 45 FC 01 F0 31 C8 88 02 83 45 FC 01 }
		$export1 = "our_sockets"
		$export2 = "get_our_pids"

	condition:
		uint16(0)==0x457f and all of them
}