
rule SECUINFRA_OBFUS_VBS_Reverse_Startup : FILE
{
	meta:
		description = "Detecs reversed StartUp Path. Sometimes used as obfuscation"
		author = "SECUINFRA Falcon Team"
		id = "ecb96e30-0ac0-530a-83af-bb030f7dce4c"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Obfuscation/vbs_obfuscation.yar#L2-L13"
		license_url = "N/A"
		logic_hash = "7b4d56d3bbe8d16d5e01fa9a021a368feb28b8b062860df76a2569966a97b8bc"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$reverse = "\\putratS\\smargorP\\uneM" wide nocase

	condition:
		filesize <200KB and $reverse
}