import "pe"


rule SIGNATURE_BASE_APT_APT41_POISONPLUG_2 : FILE
{
	meta:
		description = "Detects APT41 malware POISONPLUG"
		author = "Florian Roth (Nextron Systems)"
		id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L66-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f2ec2e91edaaf976169b1fa6645aeae75135e5d5f522e0fda2438f84d674f383"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "0055dfaccc952c99b1171ce431a02abfce5c6f8fb5dc39e4019b624a7d03bfcb"

	strings:
		$s1 = "ma_lockdown_service.dll" fullword wide
		$s2 = "acbde.dll" fullword ascii
		$s3 = "MA lockdown Service" fullword wide
		$s4 = "McAfee Agent" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <11000KB and all of them
}