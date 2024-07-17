
rule SIGNATURE_BASE_HKTL_Venom_LIB_Dec22 : FILE
{
	meta:
		description = "Detects Venom - a library that meant to perform evasive communication using stolen browser socket"
		author = "Ido Veltzman, Florian Roth"
		id = "b13b8a9c-52a4-53ac-817e-9f729fbf17c2"
		date = "2022-12-17"
		modified = "2023-12-05"
		reference = "https://github.com/Idov31/Venom"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_hktl_venom_lib.yar#L2-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fa143946479a45b272d507c3aa2b17026bfdcbb4abefd833f95ff78537568ec1"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "[ + ] Created detached hidden msedge process: " fullword ascii
		$ss1 = "WS2_32.dll" fullword ascii
		$ss2 = "WSASocketW" fullword ascii
		$ss3 = "WSADuplicateSocketW" fullword ascii
		$ss5 = "\\Device\\Afd" wide fullword
		$sx1 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe --no-startup-window" fullword wide
		$sx2 = "[ + ] Data sent!" fullword ascii
		$sx3 = "[ + ] Socket obtained!" fullword ascii
		$op1 = { 4c 8b f0 48 3b c1 48 b8 ff ff ff ff ff ff ff 7f }
		$op2 = { 48 8b cf e8 1c 34 00 00 48 8b 5c 24 30 48 8b c7 }
		$op3 = { 48 8b da 48 8b f9 45 33 f6 48 85 c9 0f 84 34 01 }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and ((3 of ($ss*) and all of ($op*)) or 2 of ($sx*)) or $x1 or all of ($sx*)
}