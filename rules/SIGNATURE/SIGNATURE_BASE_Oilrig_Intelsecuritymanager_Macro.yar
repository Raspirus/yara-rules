import "pe"


rule SIGNATURE_BASE_Oilrig_Intelsecuritymanager_Macro : FILE
{
	meta:
		description = "Detects OilRig malware"
		author = "Eyal Sela (slightly modified by Florian Roth)"
		id = "4cccc0df-a225-5500-be55-f4ae346e066e"
		date = "2018-01-19"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig.yar#L208-L233"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "35e540b87bb7425b601fad76f0ff33c60a4d91579fc50f5902d708d06fa755f6"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$one1 = "$c$m$$d$.$$" ascii wide
		$one2 = "$C$$e$r$$t$u$$t$i$$l$" ascii wide
		$one3 = "$$%$a$$p$p$$d$a$" ascii wide
		$one4 = ".$t$$x$t$$" ascii wide
		$one5 = "cu = Replace(cu, \"$\", \"\")" ascii wide
		$one6 = "Shell Environ$(\"COMSPEC\") & \" /c"
		$one7 = "echo \" & Chr(32) & cmd & Chr(32) & \" > \" & Chr(34)" ascii wide
		$two1 = "& SchTasks /Delete /F /TN " ascii wide
		$two2 = "SecurityAssist" ascii wide
		$two3 = "vbs = \"cmd.exe /c SchTasks" ascii wide
		$two4 = "/Delete /F /TN Conhost & del" ascii wide
		$two5 = "NullRefrencedException" ascii wide
		$two6 = "error has occurred in user32.dll by" ascii wide
		$two7 = "NullRefrencedException" ascii wide

	condition:
		filesize <300KB and 1 of ($one*) or 2 of ($two*)
}