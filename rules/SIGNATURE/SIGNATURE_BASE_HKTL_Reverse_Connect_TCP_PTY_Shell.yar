rule SIGNATURE_BASE_HKTL_Reverse_Connect_TCP_PTY_Shell : FILE
{
	meta:
		description = "Detects reverse connect TCP PTY shell"
		author = "Jeff Beley"
		id = "a9a90d67-774b-5b32-97c0-d7e06763f2e9"
		date = "2019-10-19"
		modified = "2023-12-05"
		reference = "https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_backconnect.py"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_python_pty_shell.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6b92077f9ff775ae3f8166f47a32aaa872fcbf7fcefc3789e5411388aac5403a"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "cae9833292d3013774bdc689d4471fd38e4a80d2d407adf9fa99bc8cde3319bf"

	strings:
		$s1 = "os.dup2(s.fileno(),1)" fullword ascii
		$s2 = "pty.spawn(\"/bin/\")" fullword ascii
		$s3 = "os.putenv(\"HISTFILE\",'/dev/null')" fullword ascii
		$s4 = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)" fullword ascii

	condition:
		filesize <1KB and 2 of them
}