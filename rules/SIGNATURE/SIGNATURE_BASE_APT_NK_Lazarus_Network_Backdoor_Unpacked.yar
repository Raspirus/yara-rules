rule SIGNATURE_BASE_APT_NK_Lazarus_Network_Backdoor_Unpacked : FILE
{
	meta:
		description = "Detects unpacked variant of Lazarus Group network backdoor"
		author = "f-secure"
		id = "8eda9e74-1a19-5510-82d8-cd2eb324629c"
		date = "2020-06-10"
		modified = "2023-12-05"
		reference = "https://labs.f-secure.com/publications/ti-report-lazarus-group-cryptocurrency-vertical"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_aug20.yar#L17-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bfc3cf400eeea332e2e44b65f9728e94af0adde76b32ed4be527b25484f80745"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$str_netsh_1 = "netsh firewall add portopening TCP %d" ascii wide nocase
		$str_netsh_2 = "netsh firewall delete portopening TCP %d" ascii wide nocase
		$str_mask_1 = "cmd.exe /c \"%s >> %s 2>&1\"" ascii wide
		$str_mask_2 = "cmd.exe /c \"%s 2>> %s\"" ascii wide
		$str_mask_3 = "%s\\%s\\%s" ascii wide
		$str_other_1 = "perflog.dat" ascii wide nocase
		$str_other_2 = "perflog.evt" ascii wide nocase
		$str_other_3 = "cbstc.log" ascii wide nocase
		$str_other_4 = "LdrGetProcedureAddress" ascii
		$str_other_5 = "NtProtectVirtualMemory" ascii

	condition:
		int16 (0)==0x5a4d and filesize <3000KB and 1 of ($str_netsh*) and 1 of ($str_mask*) and 1 of ($str_other*)
}