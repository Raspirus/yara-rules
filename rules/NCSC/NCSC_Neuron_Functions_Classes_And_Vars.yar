
rule NCSC_Neuron_Functions_Classes_And_Vars : FILE
{
	meta:
		description = "Rule for detection of Neuron based on .NET function, variable and class names"
		author = "NCSC UK"
		id = "6c785b63-637b-5343-b839-0b482cfc9cf6"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L39-L66"
		license_url = "N/A"
		hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
		logic_hash = "2e378af2ddb15ed1285eafecee1075caf958c7ff470608801c49c951e044d912"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$class1 = "StorageUtils" ascii
		$class2 = "WebServer" ascii
		$class3 = "StorageFile" ascii
		$class4 = "StorageScript" ascii
		$class5 = "ServerConfig" ascii
		$class6 = "CommandScript" ascii
		$class7 = "MSExchangeService" ascii
		$class8 = "W3WPDIAG" ascii
		$func1 = "AddConfigAsString" ascii
		$func2 = "DelConfigAsString" ascii
		$func3 = "GetConfigAsString" ascii
		$func4 = "EncryptScript" ascii
		$func5 = "ExecCMD" ascii
		$func6 = "KillOldThread" ascii
		$func7 = "FindSPath" ascii
		$var1 = "CommandTimeWait" ascii
		$dotnetMagic = "BSJB" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $dotnetMagic and 6 of them
}