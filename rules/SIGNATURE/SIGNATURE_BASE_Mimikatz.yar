import "pe"


rule SIGNATURE_BASE_Mimikatz : FILE
{
	meta:
		description = "mimikatz"
		author = "Benjamin DELPY (gentilkiwi)"
		id = "840a5b8c-a311-50bc-a099-6b8ab1492e12"
		date = "2022-11-16"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mimikatz.yar#L48-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bf972a2c0465c3bbdde6f03d91c6f479d0f66c6d3e9512355de5a973164b56a5"
		score = 75
		quality = 85
		tags = "FILE"
		tool_author = "Benjamin DELPY (gentilkiwi)"

	strings:
		$exe_x86_1 = { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2 = { 8b 4d e? 8b 45 f4 89 75 e? 89 01 85 ff 74 }
		$exe_x64_1 = { 33 ff 4? 89 37 4? 8b f3 45 85 c? 74}
		$exe_x64_2 = { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }
		$sys_x86 = { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64 = { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		( all of ($exe_x86_*)) or ( all of ($exe_x64_*)) or ( any of ($sys_*))
}