
rule SIGNATURE_BASE_Apt_CN_Tetris_JS_Advanced_1 : FILE
{
	meta:
		description = "Unique code from Jetriz, Swid & Jeniva of the Tetris framework"
		author = "@imp0rtp3 (modified by Florian Roth)"
		id = "a56f69f5-3562-52ab-9686-411019c51055"
		date = "2020-09-06"
		modified = "2023-12-05"
		reference = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_tetris.yar#L2-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ec4ba53fea05c5331ed900b8c7da4cddd4ab64e87dfc165ac18d72d22f754d87"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "var a0_0x"
		$b1 = "a0_0x" ascii
		$cx1 = "))),function(){try{var _0x"
		$cx2 = "=window)||void 0x0===_0x"
		$cx3 = "){if(opener&&void 0x0!==opener["
		$cx4 = "String['fromCharCode'](0x"
		$e1 = "')](__p__)"

	condition:
		$a1 at 0 or ( filesize <1000KB and (#b1>300 or #e1>1 or 2 of ($cx*)))
}