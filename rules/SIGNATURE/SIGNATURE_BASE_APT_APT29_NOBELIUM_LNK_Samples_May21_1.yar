rule SIGNATURE_BASE_APT_APT29_NOBELIUM_LNK_Samples_May21_1 : FILE
{
	meta:
		description = "Detects link file characteristics as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		id = "c807ab5a-f66a-5622-81b1-6e69b6df8446"
		date = "2021-05-27"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_nobelium_may21.yar#L99-L128"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "32d76bb1af76f0fc2afb76d9726bc8ec99c4be34c9d46cebab7356d8c68af11c"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "24caf54e7c3fe308444093f7ac64d6d520c8f44ea4251e09e24931bdb72f5548"

	strings:
		$a1 = "rundll32.exe" wide
		$sa1 = "IMGMountingService.dll" wide
		$sa2 = "MountImgHelper" wide
		$sb1 = "diassvcs.dll" wide
		$sb2 = "InitializeComponent" wide
		$sc1 = "MsDiskMountService.dll" wide
		$sc2 = "DiskDriveIni" wide
		$sd1 = "GraphicalComponent.dll" wide
		$sd2 = "VisualServiceComponent" wide
		$se1 = "data/mstu.dll,MicrosoftUpdateService" wide

	condition:
		uint16(0)==0x004c and filesize <4KB and $a1 and ( all of ($sa*) or all of ($sb*) or all of ($sc*) or all of ($sd*) or all of ($se*))
}