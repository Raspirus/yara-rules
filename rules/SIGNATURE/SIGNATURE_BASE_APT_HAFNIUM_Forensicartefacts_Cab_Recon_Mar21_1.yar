
rule SIGNATURE_BASE_APT_HAFNIUM_Forensicartefacts_Cab_Recon_Mar21_1 : FILE
{
	meta:
		description = "Detects suspicious CAB files used by HAFNIUM for recon activity"
		author = "Florian Roth (Nextron Systems)"
		id = "b0caf9d9-af0a-5181-85e4-6091cd6699e3"
		date = "2021-03-11"
		modified = "2023-12-05"
		reference = "https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3?u=dstepanic"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hafnium.yar#L252-L273"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "de3acb2d01ad14d73263af9e62ef7c715cde259e3f2fbbcbbb41d55589c3f0ab"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "ip.txt" ascii fullword
		$s2 = "arp.txt" ascii fullword
		$s3 = "system" ascii fullword
		$s4 = "security" ascii fullword

	condition:
		uint32(0)==0x4643534d and filesize <10000KB and ($s1 in (0..200) and $s2 in (0..200) and $s3 in (0..200) and $s4 in (0..200))
}