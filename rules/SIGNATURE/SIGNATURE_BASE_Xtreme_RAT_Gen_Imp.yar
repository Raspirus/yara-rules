rule SIGNATURE_BASE_Xtreme_RAT_Gen_Imp : FILE
{
	meta:
		description = "Detects XTREME sample analyzed in September 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "10b23099-2a87-5918-927b-f20bcba1cd70"
		date = "2017-09-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_xtreme_rat.yar#L71-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9cfd6473e7f8d1f899fe2cdbb49a4086ea7ac6151602d0964ed28b16d2d0188d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7b5082bcc8487bb65c38e34c192c2a891e7bb86ba97281352b0837debee6f1cf"

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="d0bdf112886f3d846cc7780967d8efb9" or pe.imphash()=="cc6f630f214cf890e63e899d8ebabba6" or pe.imphash()=="e0f7991d50ceee521d7190effa3c494e")
}