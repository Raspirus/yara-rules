rule SIGNATURE_BASE_Oilrig_Strings_Oct17 : FILE
{
	meta:
		description = "Detects strings from OilRig malware and malicious scripts"
		author = "Florian Roth (Nextron Systems)"
		id = "edf7c7ca-0c58-5507-8d99-83078ff8947a"
		date = "2017-10-18"
		modified = "2022-12-21"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_oct17.yar#L11-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3987fa1ccb215edeb0d36c947fd6d7a24847ea854d3f355d1aef4b000f55e710"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "%localappdata%\\srvHealth.exe" fullword wide ascii
		$x2 = "%localappdata%\\srvBS.txt" fullword wide ascii
		$x3 = "Agent Injector\\PolicyConverter\\Inner\\obj\\Release\\Inner.pdb" ascii
		$x4 = "Agent Injector\\PolicyConverter\\Joiner\\obj\\Release\\Joiner.pdb" ascii
		$s3 = ".LoadDll(\"Run\", arg, \"C:\\\\Windows\\\\" ascii

	condition:
		filesize <800KB and 1 of them
}