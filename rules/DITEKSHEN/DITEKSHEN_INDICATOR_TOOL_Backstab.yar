import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Backstab : FILE
{
	meta:
		description = "Detect Backstab tool capable of killing antimalware protected processes by leveraging sysinternals Process Explorer (ProcExp) driver"
		author = "ditekSHen"
		id = "1e514d03-9b78-5e75-9a31-02c0413e23a7"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L923-L939"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "d25c3ff4d7c120fdf7c275d11da7a321bcbdb275dcfaa699b5bb4bd66167ec92"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "NtLoadDriver: %x" fullword ascii
		$s2 = "POSIXLY_CORRECT" fullword ascii
		$s3 = "\\\\.\\PROCEXP" ascii
		$s4 = "ProcExpOpenProtectedProcess.DeviceIoControl: %" ascii
		$s5 = "ProcExpKillHandle.DeviceIoControl" ascii
		$s6 = "[%#llu] [%ws]: %ws" fullword ascii
		$s7 = "D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR" wide
		$s8 = "-k -d c:\\\\driver.sys" ascii
		$s9 = "backstab.exe -" ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}