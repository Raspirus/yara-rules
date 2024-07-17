rule SIGNATURE_BASE_Uboatrat : FILE
{
	meta:
		description = "Detects UBoat RAT Samples"
		author = "Florian Roth (Nextron Systems)"
		id = "f7f745c2-648d-5937-8d06-f5d1b6ed7e11"
		date = "2017-11-29"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_uboat_rat.yar#L9-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3d0837607d1a5efd9986eccf98f108633502a09dbf8c4c94fc0f0247060bc3a8"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "04873dbd63279228a0a4bb1184933b64adb880e874bd3d14078161d06e232c9b"
		hash2 = "7b32f401e2ad577e8398b2975ecb5c5ce68c5b07717b1e0d762f90a6fbd8add1"
		hash3 = "42d8a84cd49ff3afacf3d549fbab1fa80d5eda0c8625938b6d32e18004b0edac"
		hash4 = "6bea49e4260f083ed6b73e100550ecd22300806071f4a6326e0544272a84526c"
		hash5 = "cf832f32b8d27cf9911031910621c21bd3c20e71cc062716923304dacf4dadb7"
		hash6 = "bf7c6e911f14a1f8679c9b0c2b183d74d5accd559e17297adcd173d76755e271"

	strings:
		$s1 = "URLDownloadToFileA" ascii
		$s2 = "GetModuleFileNameW" ascii
		$s4 = "WININET.dll" ascii
		$s5 = "urlmon.dll" ascii
		$s6 = "WTSAPI32.dll" ascii
		$s7 = "IPHLPAPI.DLL" ascii
		$op1 = { 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
               69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F
               74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20
               6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00 }
		$vprotect = { 2E 76 6D 70 30 }

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3c))==0x4550 and filesize <1400KB and filesize >800KB and ( all of ($s*) and $op1 at 64 and uint16( uint32(0x3c)+11)==0x59 and $vprotect in (600..700))
}