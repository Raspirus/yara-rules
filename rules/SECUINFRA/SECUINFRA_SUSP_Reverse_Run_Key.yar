rule SECUINFRA_SUSP_Reverse_Run_Key : FILE
{
	meta:
		description = "Detects a Reversed Run Key"
		author = "SECUINFRA Falcon Team"
		id = "230bed16-278e-574c-bb9b-cf6c44a7e9cd"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Windows/windows_misc.yar#L27-L38"
		license_url = "N/A"
		logic_hash = "dcb1a7e2c688287d08ade3d75e5c3d0dde6b645889bd4ec09ce8c131d8d3265e"
		score = 65
		quality = 70
		tags = "FILE"

	strings:
		$run = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide

	condition:
		filesize <100KB and $run
}