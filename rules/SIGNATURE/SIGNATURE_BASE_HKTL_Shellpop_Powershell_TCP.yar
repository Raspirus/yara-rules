rule SIGNATURE_BASE_HKTL_Shellpop_Powershell_TCP : FILE
{
	meta:
		description = "Detects malicious powershell"
		author = "Tobias Michalski"
		id = "4f3a92db-f686-559a-9588-fb79f423c51f"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4354-L4367"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8eb484ba87fa2e10af3c59445ccb4be73db2f5ae67c59118a2e188ba02fdc957"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"

	strings:
		$ = "Something went wrong with execution of command on the target" ascii
		$ = ";[byte[]]$bytes = 0..65535|%{0};$sendbytes =" ascii

	condition:
		filesize <3KB and 1 of them
}