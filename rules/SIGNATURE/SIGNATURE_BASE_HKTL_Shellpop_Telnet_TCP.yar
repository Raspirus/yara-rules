import "pe"


rule SIGNATURE_BASE_HKTL_Shellpop_Telnet_TCP : FILE
{
	meta:
		description = "Detects malicious telnet shell"
		author = "Tobias Michalski"
		id = "dbd5cc65-c6f1-54f3-813f-7a7f9bcca184"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4384-L4397"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e900fb8c0f1fa61f242b97ac542cb1bfd691dd50523e0023e97e3b21617053d7"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "cf5232bae0364606361adafab32f19cf56764a9d3aef94890dda9f7fcd684a0e"

	strings:
		$x1 = "if [ -e /tmp/f ]; then rm /tmp/f;" ascii
		$x2 = "0</tmp/f|/bin/bash 1>/tmp/f" fullword ascii

	condition:
		filesize <3KB and 1 of them
}