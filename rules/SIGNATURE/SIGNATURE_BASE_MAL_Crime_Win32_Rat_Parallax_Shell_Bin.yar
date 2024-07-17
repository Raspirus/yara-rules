import "pe"


import "pe"


rule SIGNATURE_BASE_MAL_Crime_Win32_Rat_Parallax_Shell_Bin : FILE
{
	meta:
		description = "Detects Parallax injected code"
		author = "@VK_Intel"
		id = "6bb337ef-3156-589a-9b2f-fa1b21699433"
		date = "2020-05-05"
		modified = "2023-12-05"
		reference = "https://twitter.com/VK_Intel/status/1257714191902937088"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_rat_parallax.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6b8c71cc19ca6f066d27a4e58d9ec347ac51d245308f2c41adf2386242581610"
		score = 75
		quality = 85
		tags = "FILE"
		tlp = "white"

	strings:
		$ntdll_load = {55 8b ec 81 ec d0 08 00 00 53 56 57 e8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 33 c0 b9 18 01 00 00 f3 ?? 68 02 9f e6 6a e8 ?? ?? ?? ?? 8b d8 68 40 5e c0 84 89 ?? ?? e8 ?? ?? ?? ?? 6a 00 8b f0 68 0b 1c 64 72 53 89 ?? ?? e8 ?? ?? ?? ?? 83 c4 14 89 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 68 30 02 00 00 51 ff d0 6a 6e 58 6a 74 66 ?? ?? ?? ?? ?? ?? 58 6a 64 59 6a 6c 66 ?? ?? ?? ?? ?? ?? 58 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 33 c0 6a 2e}
		$call_func = {81 ec bc 00 00 00 8d ?? ?? 56 50 6a 00 6a 01 ff ?? ?? e8 ?? ?? ?? ?? 8b f0 83 c4 10 85 f6 0f ?? ?? ?? ?? ?? 33 c9 89 ?? ?? 39 ?? ?? 0f ?? ?? ?? ?? ?? 8b ?? ?? 53 57 8b ?? ?? 8d ?? ?? 0f ?? ?? ?? 8b ?? ?? 8d ?? ?? 8b ?? ?? 03 fa 8b df 2b da 03 ?? ?? 80 ?? ?? 0f ?? ?? ?? ?? ?? 83 ?? ?? ?? 8b c7 83 ?? ?? ?? 83 ?? ?? ?? 83 ?? ?? ?? 83 ?? ?? ?? 83 ?? ?? ?? 99 89 ?? ?? 8b ca 89 ?? ?? 8d ?? ?? 99 89 ?? ?? 89 ?? ?? 8d ?? ?? 89 ?? ?? 89 ?? ?? 8b ca 99 89 ?? ?? 89 ?? ?? 8b ca 89 ?? ?? 89 ?? ?? 8d ?? ?? 6a 40 89 ?? ??}
		$cryp_hex = {8b ec 8b ?? ?? 25 55 55 55 55 d1 e0 8b ?? ?? d1 e9 81 e1 55 55 55 55 0b c1 89 ?? ?? 8b ?? ?? 81 e2 33 33 33 33 c1 e2 02 8b ?? ?? c1 e8 02 25 33 33 33 33 0b d0 89 ?? ?? 8b ?? ?? 81 e1 0f 0f 0f 0f c1 e1 04 8b ?? ?? c1 ea 04 81 e2 0f 0f 0f 0f 0b ca 89 ?? ?? 8b ?? ?? c1 e0 18 8b ?? ?? 81 e1 00 ff 00 00 c1 e1 08 0b c1 8b ?? ?? c1 ea 08 81 e2 00 ff 00 00 0b c2 8b ?? ?? c1 e9 18 0b c1 89 ?? ?? 8b ?? ?? 5d c3}

	condition:
		uint16(0)==0x5a4d and 2 of them or all of them
}