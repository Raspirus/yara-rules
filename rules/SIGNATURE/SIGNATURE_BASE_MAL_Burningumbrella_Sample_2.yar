rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_2 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "926b4a29-ce47-559b-94e3-1fabd90f3fbe"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L33-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0c298176e5849b2b202089f27cffb7646243d19a90898bbf079a97d2f624a27e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "801a64a730fc8d80e17e59e93533c1455686ca778e6ba99cf6f1971a935eda4c"

	strings:
		$s1 = { 40 00 00 E0 63 68 72 6F 6D 67 75 78 }
		$s2 = { 40 00 00 E0 77 62 68 75 74 66 6F 61 }
		$s3 = "ActiveX Manager" wide

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and $s1 in (0..1024) and $s2 in (0..1024) and $s3
}