import "pe"


rule SIGNATURE_BASE_Keetheft_Out_Shellcode : FILE
{
	meta:
		description = "Detects component of KeeTheft - KeePass dump tool - file Out-Shellcode.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "1263ad5d-5d50-50e6-ad78-9d5e4e16634b"
		date = "2017-08-29"
		modified = "2023-12-05"
		reference = "https://github.com/HarmJ0y/KeeThief"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4014-L4028"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2d536edf1a40defc3b3aa7ce8e595c53e7dd3b7f1daea772c13319ee5bf7675e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2afb1c8c82363a0ae43cad9d448dd20bb7d2762aa5ed3672cd8e14dee568e16b"

	strings:
		$x1 = "Write-Host \"Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))\"" fullword ascii
		$x2 = "$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\\.text\\W+CODE' })[0]" fullword ascii

	condition:
		( filesize <2KB and 1 of them )
}