import "pe"


rule SIGNATURE_BASE_Apt_RU_Turla_Kazuar_Debugview_Pefeatures : FILE
{
	meta:
		description = "Turla mimicking SysInternals Tools- peFeatures"
		author = "JAG-S"
		id = "0a1675c0-8645-5288-9ef6-e68ffbfe0c3b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.epicturla.com/blog/sysinturla"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_kazuar.yar#L15-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "10c2e47e5c1885c7dc19d1fb7933c9b15911cbe4c6fba99b7f763738ae934126"
		score = 85
		quality = 85
		tags = "FILE"
		version = "2.0"
		hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash2 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"

	condition:
		uint16(0)==0x5a4d and (pe.version_info["LegalCopyright"]=="Test Copyright" and ((pe.version_info["ProductName"]=="Sysinternals DebugView" and pe.version_info["Description"]=="Sysinternals DebugView") or (pe.version_info["FileVersion"]=="4.80.0.0" and pe.version_info["Comments"]=="Sysinternals DebugView") or (pe.version_info["OriginalName"] contains "DebugView.exe" and pe.version_info["InternalName"] contains "DebugView.exe") or (pe.version_info["OriginalName"]=="Agent.exe" and pe.version_info["InternalName"]=="Agent.exe")))
}