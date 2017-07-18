explode_iso.py
================

This module explodes an ISO9660 CD/DVD image file. It uses isoparser to identify embedded objects within an ISO file. Initial research that led
to the creation of this module was discussed by Didier Stevens at https://blog.didierstevens.com/2017/07/17/quickpost-analyzing-iso-files-containing-malware/.
The isoparser library can be found at https://github.com/barneygale/isoparser

**Flags Set:** None

**Output Objects:** Files prepended with e_iso_

Installation
---
* Install isoparser (http://www.decalage.info/python/oletools)
```
pip install isoparser
```
* Put explode_iso.py in the laikaboss module installation directory:
  * /usr/local/lib/python2.7/dist-packages/laikaboss-2.0-py2.7.egg/laikaboss/modules/
* Modify dispatch.yara to include the module
```
rule type_is_iso
{
    meta:
        scan_modules = "EXPLODE_ISO"
        file_type = "iso"

    strings:
        $iso = { 43 44 30 30 31 }

    condition:
        $iso at 0x8001 and $iso at 0x8801 and $iso at 0x9001
}
```

Testing
---
You can test this LaikaBOSS module by using laika.py and the command line switch -m. 
```
laika.py -o . -m EXPLODE_ISO FCFA42FF8146BD65B49F34DB98C8B980.danger
```

Sample output
```
$ ls -l bace3fcf-1344-4ea7-801d-d718d8be7823/
total 5808

0141280a-5778-447e-8f57-d03aaf329ded
0b0b29c1-5522-426a-a5d5-203a9a92802f
0db5d9e9-4ada-4e80-b2b4-88d3028e439c
1f11a16b-4938-42b3-9046-e7a3b3300ed6
207056ee-372f-4847-8604-826d22ac9394
27a27762-1e6e-419f-86c8-45c1f02933fa
3e078c83-b8f8-4ee1-99fa-1fe95175e9f3
5eb65b16-f24f-420b-bd92-3572991cabdd
6a46bc76-4f51-4da1-a27b-dd9ec84edcda
6c590ba3-51ce-4359-8fd0-dd72ecb14616
6d0a490f-de0c-4b0a-ac48-df06469083a6
70153047-e985-4350-a9ea-84ac71bafa2e
7a1f889d-2cd8-45d8-be02-7d6774ad7973
92dc03d3-841a-4342-8d9d-657fcd4cad4b
97278c15-7e6f-45f9-a709-c5187d3b15bc
9d4852c0-cdf2-4db8-9942-c0b26c21aaab
a41d57da-6187-41a9-afba-ec7646e5d617
a5e66e66-3c70-45a9-9936-0951f574e69a
ad049cad-549f-47e0-a1d2-f41a0552ec18
b0d5a5ab-cd19-4e64-9ca1-6f06b9587171
b8e76b47-dae7-4169-b981-72ae845c75df
bace3fcf-1344-4ea7-801d-d718d8be7823
c5984653-56e6-4424-95d0-a9b700e839a8
d770287b-b374-4cd0-97f0-3f18ba395132
e_iso_bbe79d0eeda6e1d97a24626dfca8ef5b -> 27a27762-1e6e-419f-86c8-45c1f02933fa
e_iso_c93a80049746653289db0579b253a59d -> b0d5a5ab-cd19-4e64-9ca1-6f06b9587171
e_zip_[Content_Types].xml -> 9d4852c0-cdf2-4db8-9942-c0b26c21aaab
e_zip_customXml_item1.xml -> c5984653-56e6-4424-95d0-a9b700e839a8
e_zip_customXml_itemProps1.xml -> a41d57da-6187-41a9-afba-ec7646e5d617
e_zip_customXml__rels_item1.xml.rels -> 6d0a490f-de0c-4b0a-ac48-df06469083a6
e_zip_docProps_app.xml -> 6c590ba3-51ce-4359-8fd0-dd72ecb14616
e_zip_docProps_core.xml -> 97278c15-7e6f-45f9-a709-c5187d3b15bc
e_zip__rels_.rels -> 6a46bc76-4f51-4da1-a27b-dd9ec84edcda
e_zip_word_document.xml -> a5e66e66-3c70-45a9-9936-0951f574e69a
e_zip_word_fontTable.xml -> 0db5d9e9-4ada-4e80-b2b4-88d3028e439c
e_zip_word_media_image1.png -> 70153047-e985-4350-a9ea-84ac71bafa2e
e_zip_word_numbering.xml -> 92dc03d3-841a-4342-8d9d-657fcd4cad4b
e_zip_word__rels_document.xml.rels -> 7a1f889d-2cd8-45d8-be02-7d6774ad7973
e_zip_word_settings.xml -> 3e078c83-b8f8-4ee1-99fa-1fe95175e9f3
e_zip_word_styles.xml -> 5eb65b16-f24f-420b-bd92-3572991cabdd
e_zip_word_theme_theme1.xml -> 1f11a16b-4938-42b3-9046-e7a3b3300ed6
e_zip_word_webSettings.xml -> 207056ee-372f-4847-8604-826d22ac9394
FCFA42FF8146BD65B49F34DB98C8B980.danger -> bace3fcf-1344-4ea7-801d-d718d8be7823
result.json

```
Running file against the directory shows the e_iso objects embedded in the ISO image were a Word 2007+ document and a Windows PE32 file.

```
$ file bace3fcf-1344-4ea7-801d-d718d8be7823/*
...
bace3fcf-1344-4ea7-801d-d718d8be7823/27a27762-1e6e-419f-86c8-45c1f02933fa:    Microsoft Word 2007+
bace3fcf-1344-4ea7-801d-d718d8be7823/b0d5a5ab-cd19-4e64-9ca1-6f06b9587171:    PE32 executable (GUI) Intel 80386, for MS Windows
...
```
