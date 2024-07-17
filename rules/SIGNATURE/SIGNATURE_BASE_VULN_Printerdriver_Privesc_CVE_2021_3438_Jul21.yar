rule SIGNATURE_BASE_VULN_Printerdriver_Privesc_CVE_2021_3438_Jul21 : FILE
{
	meta:
		description = "Detects affected drivers with PE timestamps older than the date of the initial report"
		author = "Florian Roth (Nextron Systems)"
		id = "34cd648a-3e3f-5832-8abe-18507931eb3d"
		date = "2021-07-20"
		modified = "2023-12-05"
		reference = "https://labs.sentinelone.com/cve-2021-3438-16-years-in-hiding-millions-of-printers-worldwide-vulnerable/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vul_cve_2021_3438_printdriver.yar#L4-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b58c2623c8fb84162c1c9390d0398639061ed5b1d4a8e007685e6fabe42bde54"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "7cc9ba2df7b9ea6bb17ee342898edd7f54703b93b6ded6a819e83a7ee9f938b4"

	strings:
		$s1 = "This String is from Device Driver@@@@@ !!!" ascii
		$s2 = "\\DosDevices\\ssportc" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of ($s*) and 1613606400>=pe.timestamp
}