
rule COD3NYM_SUSP_Direct_Syscall_Shellcode_Invocation_Jan24 : FILE
{
	meta:
		description = "Detects direct syscall evasion technqiue using NtProtectVirtualMemory to invoke shellcode"
		author = "Jonathan Peters"
		id = "2a0ce887-299d-5aad-bed3-3e698b4dea79"
		date = "2024-01-14"
		modified = "2024-01-14"
		reference = "https://unprotect.it/technique/evasion-using-direct-syscalls/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/other/susp_direct_syscall_shellcode_invocation.yar#L1-L14"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "f7cd214e7460c539d6f8d02b6650098e3983862ff658b76ea02c33f5a45fc836"
		logic_hash = "b5b0ad86289a4e2af7cdc909192f4dc9325c1763259f40adcc1e60c088c9e4f3"
		score = 65
		quality = 80
		tags = "FILE"

	strings:
		$ = { B8 40 00 00 00 67 4C 8D 08 49 89 CA 48 C7 C0 50 00 00 00 0F 05 [4-8] 4C 8D 3D 02 00 00 00 FF E0 }

	condition:
		all of them and filesize <2MB
}