rule SIGNATURE_BASE_HKTL_Shellpop_Netcat : FILE
{
	meta:
		description = "Detects suspcious netcat shellpop"
		author = "Tobias Michalski"
		id = "cd55e912-b57b-5fce-98eb-5a0cd27a6e4d"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4413-L4428"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2c61da27d4bc455a9f2555fcc1c5cce7cead226a5900eeed1aaf622616051b79"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "98e3324f4c096bb1e5533114249a9e5c43c7913afa3070488b16d5b209e015ee"

	strings:
		$s1 = "if [ -e /tmp/f ]; then rm /tmp/f;" ascii
		$s2 = "fi;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc" ascii
		$s4 = "mknod /tmp/f p && nc" ascii
		$s5 = "</tmp/f|/bin/bash 1>/tmp/f" ascii

	condition:
		filesize <2KB and 1 of them
}