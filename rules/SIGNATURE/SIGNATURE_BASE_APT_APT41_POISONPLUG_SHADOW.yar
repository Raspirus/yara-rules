rule SIGNATURE_BASE_APT_APT41_POISONPLUG_SHADOW : FILE
{
	meta:
		description = "Detects APT41 malware POISONPLUG SHADOW"
		author = "Florian Roth (Nextron Systems)"
		id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L33-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fc923c7e85f3870e08a077b344e575d3c349fa02f3d218a9a7ec31992f14866b"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8"

	condition:
		uint16(0)==0x5a4d and filesize <500KB and pe.imphash()=="c67de089f2009b21715744762fc484e8"
}