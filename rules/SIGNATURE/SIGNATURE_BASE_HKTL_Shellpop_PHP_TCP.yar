rule SIGNATURE_BASE_HKTL_Shellpop_PHP_TCP : FILE
{
	meta:
		description = "Detects malicious PHP shell"
		author = "Tobias Michalski"
		id = "3bafc225-62e5-5183-84aa-9c3406b6c444"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4339-L4352"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8ffab71130b4fa6efbe9864f97c33fed9359f79d51b84e8f952c911f24d1496c"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0412e1ab9c672abecb3979a401f67d35a4a830c65f34bdee3f87e87d060f0290"

	strings:
		$x1 = "php -r \"\\$sock=fsockopen" ascii
		$x2 = ";exec('/bin/sh -i <&3 >&3 2>&3');\"" ascii

	condition:
		filesize <3KB and all of them
}