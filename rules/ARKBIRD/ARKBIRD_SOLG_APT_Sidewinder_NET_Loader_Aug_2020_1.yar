rule ARKBIRD_SOLG_APT_Sidewinder_NET_Loader_Aug_2020_1 : FILE
{
	meta:
		description = "Detected the NET loader used by SideWinder group (August 2020)"
		author = "Arkbird_SOLG"
		id = "7334a3b8-cd56-5820-a073-5bd22076644f"
		date = "2020-08-24"
		modified = "2020-08-24"
		reference = "https://twitter.com/ShadowChasing1/status/1297902086747598852"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-24/SideWinder/APT_SideWinder_NET_Loader_Aug_2020_1.yar#L3-L21"
		license_url = "N/A"
		logic_hash = "b40127cd845d75ef81eb230c12635da00dd77fc53e5886c253a2466627aa8534"
		score = 75
		quality = 73
		tags = "FILE"
		hash1 = "4a0947dd9148b3d5922651a6221afc510afcb0dfa69d08ee69429c4c75d4c8b4"

	strings:
		$s1 = "DUSER.dll" fullword wide
		$s2 = "UHJvZ3JhbQ==" fullword wide
		$s3 = ".tmp           " fullword wide
		$s4 = "U3RhcnQ=" fullword wide
		$s5 = "Gadgets" fullword ascii
		$s6 = "AdapterInterfaceTemplateObject" fullword ascii
		$s7 = "FileRipper" fullword ascii
		$s8 = "copytight @" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <4KB and ((pe.exports("FileRipper") and pe.exports("Gadgets")) and 5 of them )
}