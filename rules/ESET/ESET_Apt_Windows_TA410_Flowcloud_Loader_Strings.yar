rule ESET_Apt_Windows_TA410_Flowcloud_Loader_Strings : FILE
{
	meta:
		description = "Matches various strings found in TA410 FlowCloud first stage."
		author = "ESET Research"
		id = "a3fb894f-8e26-5cbd-a1f2-8a9ab1db0901"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L379-L415"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "3c90723e009ffe2603910566ac52a324256676ee3ff128d94427681010e10e8b"
		score = 75
		quality = 78
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$key = "y983nfdicu3j2dcn09wur9*^&initialize(y4r3inf;'fdskaf'SKF"
		$s2 = "startModule" fullword
		$s4 = "auto_start_module" wide
		$s5 = "load_main_module_after_install" wide
		$s6 = "terminate_if_fail" wide
		$s7 = "clear_run_mru" wide
		$s8 = "install_to_vista" wide
		$s9 = "load_ext_module" wide
		$s10 = "sll_only" wide
		$s11 = "fail_if_already_installed" wide
		$s12 = "clear_hardware_info" wide
		$s13 = "av_check" wide fullword
		$s14 = "check_rs" wide
		$s15 = "check_360" wide
		$s16 = "responsor.dat" wide ascii
		$s17 = "auto_start_after_install_check_anti" wide fullword
		$s18 = "auto_start_after_install" wide fullword
		$s19 = "extern_config.dat" wide fullword
		$s20 = "is_hhw" wide fullword
		$s21 = "SYSTEM\\Setup\\PrintResponsor" wide
		$event = "Global\\Event_{201a283f-e52b-450e-bf44-7dc436037e56}" wide ascii
		$s23 = "invalid encrypto hdr while decrypting"

	condition:
		uint16(0)==0x5a4d and ($key or $event or 5 of ($s*))
}