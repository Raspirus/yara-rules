rule SIGNATURE_BASE_APT_APT41_POISONPLUG : FILE
{
	meta:
		description = "Detects APT41 malware POISONPLUG"
		author = "Florian Roth (Nextron Systems)"
		id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L84-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "34459c2a8a13b8084c93a640723a3e2b67d2f695ff84ab63f4e313cacc458f32"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "2eea29d83f485897e2bac9501ef000cc266ffe10019d8c529555a3435ac4aabd"
		hash2 = "5d971ed3947597fbb7e51d806647b37d64d9fe915b35c7c9eaf79a37b82dab90"
		hash3 = "f4d57acde4bc546a10cd199c70cdad09f576fdfe66a36b08a00c19ff6ae19661"
		hash4 = "3e6c4e97cc09d0432fbbbf3f3e424d4aa967d3073b6002305cd6573c47f0341f"

	strings:
		$s1 = "TSMSISrv.DLL" fullword wide
		$s2 = "[-]write failed[%d]" fullword ascii
		$s3 = "[-]load failed" fullword ascii
		$s4 = "Remote Desktop Services" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and (pe.imphash()=="1b074ef7a1c0888ef31337c8ad2f2e0a" or 2 of them )
}