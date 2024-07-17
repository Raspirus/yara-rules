rule EMBEERESEARCH_Win_Cobaltstrike_Pipe_Strings_Nov_2023 : FILE
{
	meta:
		description = "Detects default strings related to cobalt strike named pipes"
		author = "Matthew @ Embee_Research"
		id = "9237f4e8-b9c4-54cb-9cb2-999d267392af"
		date = "2023-11-04"
		modified = "2023-11-04"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_cobaltstrike_pipe_strings_nov_2023.yar#L1-L24"
		license_url = "N/A"
		hash = "99986d438ec146bbb8b5faa63ce47264750a8fdf508a4d4250a8e1e3d58377fd"
		hash = "090402a6e2db12cbdd3a889b7b46bb7702acc0cad37d87ff201230b618fe7ed5"
		hash = "eb2b263937f8d28aa9df7277b6f25d10604a5037d5644c98ee0ab8f7a25db7b4"
		logic_hash = "ff17fe9d04d9ad6aa5c034b69d412b0d62c48c537c3a54a465761e27e9255e6d"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "%c%c%c%c%c%cMSSE-%d-server"
		$s2 = "ConnectNamedPipe"
		$s3 = "CreateNamedPipeA"
		$s4 = "TlsGetValue"

	condition:
		( all of ($s*)) and filesize <500KB
}