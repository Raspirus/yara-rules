rule RUSSIANPANDA_Nitrogen_Python311_Rule : FILE
{
	meta:
		description = "Detects side-loaded Python311 DLL for the new Nitrogen campaign 10-23-2023"
		author = "RussianPanda"
		id = "608d20b2-24f8-5c95-bab5-83748a7bf3b1"
		date = "2023-10-24"
		modified = "2023-12-11"
		reference = "https://www.esentire.com/blog/persistent-connection-established-nitrogen-campaign-leverages-dll-side-loading-technique-for-c2-communication"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Nitrogen/nitrogen_python311.yar#L3-L21"
		license_url = "N/A"
		logic_hash = "04db05b3b130c9de3ff02a6a16775be9d3a50d3025bcf1e075ae56c751304154"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = { 68 62 6F 6B 62 69 30 2F }
		$s2 = { 48 B8 ?? ?? ?? ?? ?? ?? ?? 00 48 89 44 24 5C }
		$s3 = { 48 8B 05 ?? ?? 09 00}

	condition:
		all of ($s*) and uint16(0)==0x5A4D and pe.exports("nop")
}