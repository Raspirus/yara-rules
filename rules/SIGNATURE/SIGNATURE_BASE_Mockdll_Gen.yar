
rule SIGNATURE_BASE_Mockdll_Gen : FILE
{
	meta:
		description = "Detects MockDll - regsvr DLL loader"
		author = "Florian Roth (Nextron Systems)"
		id = "904a0649-27e7-5024-aa6b-ddb23bba6202"
		date = "2017-10-18"
		modified = "2023-12-05"
		reference = "https://goo.gl/MZ7dRg"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_leviathan.yar#L57-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cbe7b816199d251bfdc751f46bd95da6f0447ebd56f564619d24eb08bbd4a2c7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "bfc5c6817ff2cc4f3cd40f649e10cc9ae1e52139f35fdddbd32cb4d221368922"
		hash2 = "80b931ab1798d7d8a8d63411861cee07e31bb9a68f595f579e11d3817cfc4aca"

	strings:
		$x1 = "mock_run_ini_Win32.dll" fullword ascii
		$x2 = "mock_run_ini_x64.dll" fullword ascii
		$s1 = "RealCmd=%s %s" fullword ascii
		$s2 = "MockModule=%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and (1 of ($x*) or 2 of them )
}