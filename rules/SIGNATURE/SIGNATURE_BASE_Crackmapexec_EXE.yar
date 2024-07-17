rule SIGNATURE_BASE_Crackmapexec_EXE : FILE
{
	meta:
		description = "Detects CrackMapExec hack tool"
		author = "Florian Roth (Nextron Systems)"
		id = "9fcfba98-7ba1-5810-99b7-62ad2b1aa4c0"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4139-L4155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fa05fa41d6aaed45a9b44806a310fdb584874f7eb382e576b36e6d1db87cef88"
		score = 85
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"

	strings:
		$s1 = "core.scripts.secretsdump(" ascii
		$s2 = "core.scripts.samrdump(" ascii
		$s3 = "core.uacdump(" ascii

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and 2 of them
}