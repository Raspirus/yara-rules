
rule SIGNATURE_BASE_Badrabbit_Mimikatz_Comp : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "52affd3f-6bf9-55f6-92a5-69314a2e76e0"
		date = "2017-10-25"
		modified = "2023-12-05"
		reference = "https://pastebin.com/Y7pJv3tK"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_badrabbit.yar#L42-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9d12d9331686a54e8d32f94761e4889710bbd2432d4cb2e4e7e3f21ef6aa082a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2f8c54f9fa8e47596a3beff0031f85360e56840c77f71c6a573ace6f46412035"

	strings:
		$s1 = "%lS%lS%lS:%lS" fullword wide
		$s2 = "lsasrv" fullword wide
		$s3 = "CredentialKeys" ascii
		$s4 = { 50 72 69 6D 61 72 79 00 6D 00 73 00 76 00 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 3 of them )
}