import "pe"


rule SIGNATURE_BASE_HKTL_Shellpop_Python : FILE
{
	meta:
		description = "Detects malicious python shell"
		author = "Tobias Michalski"
		id = "62fe0ae9-422e-5021-8a67-e88ff4bd2cf3"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4325-L4337"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e4c35bb739eeabf0de558ee1b97225ed4eb3198e7e6db1817348115b848146c7"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "aee1c9e45a1edb5e462522e266256f68313e2ff5956a55f0a84f33bc6baa980b"

	strings:
		$ = "os.putenv('HISTFILE', '/dev/null');" ascii

	condition:
		filesize <2KB and 1 of them
}