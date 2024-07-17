import "pe"


rule SIGNATURE_BASE_Honeybee_Dropper_Maldoc : FILE
{
	meta:
		description = "Detects samples from Operation Honeybee"
		author = "Florian Roth (Nextron Systems)"
		id = "4e8dec29-2c0a-5760-91c9-88f67505a7f1"
		date = "2018-03-03"
		modified = "2023-12-05"
		reference = "https://goo.gl/JAHZVL"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_op_honeybee.yar#L13-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8bc680a59a7bd269eea001c2c74e41ecd93a9b848210779fc7d9c24dfab7767a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "86981680172bbf0865e7693fe5a2bbe9b3ba12b3f1a1536ef67915daab78004c"
		hash2 = "0d4352322160339f87be70c2f3fe096500cfcdc95a8dea975fdfc457bd347c44"

	strings:
		$x1 = "cmd /c expand %TEMP%\\setup.cab -F:* %SystemRoot%\\System32"
		$x2 = "del /f /q %TEMP%\\setup.cab && cliconfg.exe"
		$s1 = "SELECT * FROM Win32_Processor" fullword ascii
		$s2 = "\"cmd /c `wusa " fullword ascii
		$s3 = "sTempPathP" fullword ascii
		$s4 = "sTempFile" fullword ascii
		$s5 = "GetObjectz" fullword ascii
		$s6 = "\\setup.cab" ascii

	condition:
		uint16(0)==0xcfd0 and filesize <400KB and (1 of ($x*) or 4 of them )
}