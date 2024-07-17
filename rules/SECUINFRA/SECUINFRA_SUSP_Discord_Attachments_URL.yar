import "pe"


rule SECUINFRA_SUSP_Discord_Attachments_URL : PE DOWNLOAD FILE
{
	meta:
		description = "Detects a PE file that contains an Discord Attachments URL. This is often used by Malware to download further payloads"
		author = "SECUINFRA Falcon Team"
		id = "bf81920b-f8ab-594a-aa45-d92446411113"
		date = "2022-02-19"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/exe.yar#L3-L16"
		license_url = "N/A"
		logic_hash = "3270b74506e520064361379b274f44a467c55bdcd3d8456967e864526aca8521"
		score = 65
		quality = 70
		tags = "PE, DOWNLOAD, FILE"
		version = "0.1"

	strings:
		$url = "cdn.discordapp.com/attachments" nocase wide

	condition:
		uint16(0)==0x5a4d and $url
}