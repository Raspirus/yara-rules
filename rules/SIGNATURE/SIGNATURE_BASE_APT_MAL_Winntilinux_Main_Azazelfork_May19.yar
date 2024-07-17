rule SIGNATURE_BASE_APT_MAL_Winntilinux_Main_Azazelfork_May19 : FILE
{
	meta:
		description = "Detection of Linux variant of Winnti"
		author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
		id = "a1693e2d-4d89-5cc7-ab14-c8feb000638a"
		date = "2019-05-15"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_linux.yar#L18-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "ae9d6848f33644795a0cc3928a76ea194b99da3c10f802db22034d9f695a0c23"
		logic_hash = "3ff38795179f6c32f2ff014b06ac126ae3a0de3fe7515f0e49f12f9c8ff14b43"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		TLP = "White"

	strings:
		$uuid_lookup = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null"
		$dbg_msg = "[advNetSrv] can not create a PF_INET socket"
		$rtti_name1 = "CNetBase"
		$rtti_name2 = "CMyEngineNetEvent"
		$rtti_name3 = "CBufferCache"
		$rtti_name4 = "CSocks5Base"
		$rtti_name5 = "CDataEngine"
		$rtti_name6 = "CSocks5Mgr"
		$rtti_name7 = "CRemoteMsg"

	condition:
		uint16(0)==0x457f and (($dbg_msg and 1 of ($rtti*)) or (5 of ($rtti*)) or ($uuid_lookup and 2 of ($rtti*)))
}