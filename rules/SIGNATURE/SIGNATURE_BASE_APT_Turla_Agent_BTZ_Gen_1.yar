rule SIGNATURE_BASE_APT_Turla_Agent_BTZ_Gen_1 : FILE
{
	meta:
		description = "Detects Turla Agent.BTZ"
		author = "Florian Roth (Nextron Systems)"
		id = "d5e1dd3d-4f03-5f79-898b-e612d2758b60"
		date = "2018-06-16"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_agent_btz.yar#L75-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8616d95e683f213916f06a7bf672ced90b2fa55cb4331176021614b4f0b03aed"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "c905f2dec79ccab115ad32578384008696ebab02276f49f12465dcd026c1a615"

	strings:
		$x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii
		$s1 = "release mutex - %u (%u)(%u)" fullword ascii
		$s2 = "\\system32\\win.com" ascii
		$s3 = "Command Id:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
		$s4 = "MakeFile Error(%d) copy file to temp file %s" fullword ascii
		$s5 = "%s%%s08x.tmp" fullword ascii
		$s6 = "Run instruction: %d ID:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
		$s7 = "Mutex_Log" fullword ascii
		$s8 = "%s\\system32\\winview.ocx" fullword ascii
		$s9 = "Microsoft(R) Windows (R) Operating System" fullword wide
		$s10 = "Error: pos(%d) > CmdSize(%d)" fullword ascii
		$s11 = "\\win.com" ascii
		$s12 = "Error(%d) run %s " fullword ascii
		$s13 = "%02d.%02d.%04d Log begin:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="9d0d6daa47d6e6f2d80eb05405944f87" or (pe.exports("Entry") and pe.exports("InstallM") and pe.exports("InstallS")) or $x1 or 3 of them ) or (5 of them )
}