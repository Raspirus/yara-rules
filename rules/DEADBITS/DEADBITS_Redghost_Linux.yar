
rule DEADBITS_Redghost_Linux : POSTEXPLOITATION LINUXMALWARE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "f598e115-f821-5932-aa14-5254bf28092c"
		date = "2019-08-07"
		modified = "2019-08-08"
		reference = "https://github.com/d4rk007/RedGhost/"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/RedGhost_Linux.yara#L1-L45"
		license_url = "N/A"
		logic_hash = "0b12a0eda0a3b65c3da787770afb010eb5cd36426d41c04aca862ae1b01ab770"
		score = 75
		quality = 80
		tags = "POSTEXPLOITATION, LINUXMALWARE"
		Author = "Adam M. Swanda"

	strings:
		$name = "[ R E D G H O S T - P O S T  E X P L O I T - T O O L]" ascii
		$feature0 = "Payloads" ascii
		$feature1 = "SudoInject" ascii
		$feature2 = "lsInject" ascii
		$feature3 = "Crontab" ascii
		$feature4 = "GetRoot" ascii
		$feature5 = "Clearlogs" ascii
		$feature6 = "MassinfoGrab" ascii
		$feature7 = "CheckVM" ascii
		$feature8 = "MemoryExec" ascii
		$feature9 = "BanIP" ascii
		$func0 = "checkVM(){" ascii
		$func1 = "memoryexec(){" ascii
		$func2 = "banip(){" ascii
		$func3 = "linprivesc(){" ascii
		$func4 = "dirty(){" ascii
		$func5 = "Ocr(){" ascii
		$func6 = "clearlog(){" ascii
		$func7 = "conmethods(){" ascii
		$func8 = "add2sys(){" ascii

	condition:
		( uint16be(0x0)==0x2321 and for any i in (0..64) : ( uint16be(i)==0x2f62 and uint8(i+2)==0x68)) and ($name or 5 of them )
}