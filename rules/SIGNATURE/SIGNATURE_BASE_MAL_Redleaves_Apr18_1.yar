import "pe"


rule SIGNATURE_BASE_MAL_Redleaves_Apr18_1 : FILE
{
	meta:
		description = "Detects RedLeaves malware"
		author = "Florian Roth (Nextron Systems)"
		id = "578b40d7-6818-56d5-92ce-535141c0aa8e"
		date = "2018-05-01"
		modified = "2023-12-05"
		reference = "https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt10_redleaves.yar#L33-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e34b95e96de88aef20050b6b9580600365284117918c24f76c884b089fa20623"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "f6449e255bc1a9d4a02391be35d0dd37def19b7e20cfcc274427a0b39cb21b7b"
		hash2 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"
		hash3 = "d956e2ff1b22ccee2c5d9819128103d4c31ecefde3ce463a6dea19ecaaf418a1"

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (pe.imphash()=="7a861cd9c495e1d950a43cb708a22985" or pe.imphash()=="566a7a4ef613a797389b570f8b4f79df")
}