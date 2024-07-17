rule CHECK_POINT_Injector_ZZ_Dotrunpex : FILE
{
	meta:
		description = "Detects new version of dotRunpeX - configurable .NET injector"
		author = "Jiri Vinopal (jiriv)"
		id = "6cdbe54b-2e8d-5f7b-81ac-983236d1449f"
		date = "2022-10-30"
		modified = "2023-04-10"
		reference = "https://research.checkpoint.com/2023/dotrunpex-demystifying-new-virtualized-net-injector-used-in-the-wild/"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Checkpoint/injector_ZZ_dotRunpeX.yar#L1-L58"
		license_url = "N/A"
		logic_hash = "ca4336533f90598a6b6f594036e20595073e0e7cab5fcd186995c5c7f2be287e"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "373a86e36f7e808a1db263b4b49d2428df4a13686da7d77edba7a6dd63790232"
		hash2 = "41ea8f9a9f2a7aeb086dedf8e5855b0409f31e7793cbba615ca0498e47a72636"
		hash3 = "5e3588e8ddebd61c2bd6dab4b87f601bd6a4857b33eb281cb5059c29cfe62b80"
		hash4 = "8c451b84d9579b625a7821ad7ddcb87bdd665a9e6619eaecf6ab93cd190cf504"
		hash5 = "8fa81f6341b342afa40b7dc76dd6e0a1874583d12ea04acf839251cb5ca61591"
		hash6 = "cd4c821e329ec1f7bfe7ecd39a6020867348b722e8c84a05c7eb32f8d5a2f4db"
		hash7 = "fa8a67642514b69731c2ce6d9e980e2a9c9e409b3947f2c9909d81f6eac81452"
		hash8 = "eb2e2ac0f5f51d90fe90b63c3c385af155b2fee30bc3dc6309776b90c21320f5"

	strings:
		$implmap1 = "VirtualAllocEx"
		$implmap2 = "CreateProcess"
		$implmap3 = "CreateRemoteThread"
		$implmap4 = "Wow64SetThreadContext"
		$implmap5 = "Wow64GetThreadContext"
		$implmap6 = "NtResumeThread"
		$implmap7 = "ZwUnmapViewOfSection"
		$implmap8 = "NtWriteVirtualMemory"
		$implmap9 = "MessageBox"
		$implmap10 = "Wow64DisableWow64FsRedirection"
		$implmap11 = "Wow64RevertWow64FsRedirection"
		$implmap12 = "CreateFile"
		$implmap13 = "RtlInitUnicodeString"
		$implmap14 = "NtLoadDriver"
		$implmap15 = "NtUnloadDriver"
		$implmap16 = "OpenProcessToken"
		$implmap17 = "LookupPrivilegeValue"
		$implmap18 = "AdjustTokenPrivileges"
		$implmap19 = "CloseHandle"
		$implmap20 = "NtQuerySystemInformation"
		$implmap21 = "DeviceIoControl"
		$implmap22 = "GetProcessHeap"
		$implmap23 = "HeapFree"
		$implmap24 = "HeapAlloc"
		$implmap25 = "GetProcAddress"
		$implmap26 = "CopyMemory"
		$modulerefKernel1 = "Kernel32"
		$modulerefKernel2 = "kernel32"
		$modulerefNtdll1 = "Ntdll"
		$modulerefNtdll2 = "ntdll"
		$modulerefAdvapi1 = "Advapi32"
		$modulerefAdvapi2 = "advapi32"
		$regPath = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\TaskKill" wide
		$rsrcName = "BIDEN_HARRIS_PERFECT_ASSHOLE" wide
		$koiVM1 = "KoiVM"
		$koiVM2 = "#Koi"

	condition:
		uint16(0)==0x5a4d and uint16( uint32(0x3c))==0x4550 and ($regPath or $rsrcName or 1 of ($koiVM*)) and 24 of ($implmap*) and 1 of ($modulerefKernel*) and 1 of ($modulerefNtdll*) and 1 of ($modulerefAdvapi*)
}