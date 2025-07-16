from enum import Enum


class Region(Enum):
    TAIPEI_CITY = 1
    NEW_TAIPEI_CITY = 3
    TAOYUAN_CITY = 6


class Section(Enum):
    # taipei city
    DAAN_DISTRICT = 5
    NEIHU_DISTRICT = 10
    SHILIN_DISTRICT = 8
    WENSHAN_DISTRICT = 12
    BEITOU_DISTRICT = 9
    ZHONGSHAN_DISTRICT = 3
    XINYI_DISTRICT = 7
    SONGSHAN_DISTRICT = 4
    WANHUA_DISTRICT = 6
    ZHONGZHENG_DISTRICT = 1
    DATONG_DISTRICT = 2
    NANGANG_DISTRICT = 11

    # new taipei city
    BANQIAO_DISTRICT = 26
    XINZHUANG_DISTRICT = 44
    ZHONGHE_DISTRICT = 38
    SANCHONG_DISTRICT = 43
    XINDIAN_DISTRICT = 34
    TUCHENG_DISTRICT = 39
    YONGHE_DISTRICT = 37
    XIZHI_DISTRICT = 27
    LUZHOU_DISTRICT = 47
    DANSHUI_DISTRICT = 50
    SHULIN_DISTRICT = 41
    LINKOU_DISTRICT = 46
    SANXIA_DISTRICT = 40
    WUGU_DISTRICT = 48
    YINGGE_DISTRICT = 42
    TAISHAN_DISTRICT = 45
    BALI_DISTRICT = 49
    RUIFANG_DISTRICT = 30
    SHENKENG_DISTRICT = 28
    SANZHI_DISTRICT = 51
    WANLI_DISTRICT = 20
    JINSHAN_DISTRICT = 21
    GONGLIAO_DISTRICT = 33
    SHIMEN_DISTRICT = 52
    SHUANGXI_DISTRICT = 32
    SHIDING_DISTRICT = 29
    PINGLIN_DISTRICT = 35
    WULAI_DISTRICT = 36
    PINGXI_DISTRICT = 31


class Layout(Enum):
    ONE_BEDROOM = 1
    TWO_BEDROOMS = 2
    THREE_BEDROOMS = 3
    FOUR_BEDROOMS_AND_ABOVE = 4


translations_en = {
    Region.TAIPEI_CITY: "Taipei City",
    Region.NEW_TAIPEI_CITY: "New Taipei City",
    Region.TAOYUAN_CITY: "Taoyuan City",
    Layout.ONE_BEDROOM: "1 bedroom",
    Layout.TWO_BEDROOMS: "2 bedrooms",
    Layout.THREE_BEDROOMS: "3 bedrooms",
    Layout.FOUR_BEDROOMS_AND_ABOVE: "3+ bedrooms",
    # taipei city
    Section.DAAN_DISTRICT: "Da'an District",
    Section.NEIHU_DISTRICT: "Neihu District",
    Section.SHILIN_DISTRICT: "Shilin District",
    Section.WENSHAN_DISTRICT: "Wenshan District",
    Section.BEITOU_DISTRICT: "Beitou District",
    Section.ZHONGSHAN_DISTRICT: "Zhongshan District",
    Section.XINYI_DISTRICT: "Xinyi District",
    Section.SONGSHAN_DISTRICT: "Songshan District",
    Section.WANHUA_DISTRICT: "Wanhua District",
    Section.ZHONGZHENG_DISTRICT: "Zhongzheng District",
    Section.DATONG_DISTRICT: "Datong District",
    Section.NANGANG_DISTRICT: "Nangang District",
    # new taipei city
    Section.BANQIAO_DISTRICT: "Banqiao District",
    Section.XINZHUANG_DISTRICT: "Xinzhuang District",
    Section.ZHONGHE_DISTRICT: "Zhonghe District",
    Section.SANCHONG_DISTRICT: "Sanchong District",
    Section.XINDIAN_DISTRICT: "Xindian District",
    Section.TUCHENG_DISTRICT: "Tucheng District",
    Section.YONGHE_DISTRICT: "Yonghe District",
    Section.XIZHI_DISTRICT: "Xizhi District",
    Section.LUZHOU_DISTRICT: "Luzhou District",
    Section.DANSHUI_DISTRICT: "Danshui District",
    Section.SHULIN_DISTRICT: "Shulin District",
    Section.LINKOU_DISTRICT: "Linkou District",
    Section.SANXIA_DISTRICT: "Sanxia District",
    Section.WUGU_DISTRICT: "Wugu District",
    Section.YINGGE_DISTRICT: "Yingge District",
    Section.TAISHAN_DISTRICT: "Taishan District",
    Section.BALI_DISTRICT: "Bali District",
    Section.RUIFANG_DISTRICT: "Ruifang District",
    Section.SHENKENG_DISTRICT: "Shenkeng District",
    Section.SANZHI_DISTRICT: "Sanzhi District",
    Section.WANLI_DISTRICT: "Wanli District",
    Section.JINSHAN_DISTRICT: "Jinshan District",
    Section.GONGLIAO_DISTRICT: "Gongliao District",
    Section.SHIMEN_DISTRICT: "Shimen District",
    Section.SHUANGXI_DISTRICT: "Shuangxi District",
    Section.SHIDING_DISTRICT: "Shiding District",
    Section.PINGLIN_DISTRICT: "Pinglin District",
    Section.WULAI_DISTRICT: "Wulai District",
    Section.PINGXI_DISTRICT: "Pingxi District",
}

translations_zh = {
    Region.TAIPEI_CITY: "台北市",
    Region.NEW_TAIPEI_CITY: "新北市",
    Region.TAOYUAN_CITY: "桃園市",
    Layout.ONE_BEDROOM: "1房",
    Layout.TWO_BEDROOMS: "2房",
    Layout.THREE_BEDROOMS: "3房",
    Layout.FOUR_BEDROOMS_AND_ABOVE: "4房以上",
    # taipei city
    Section.DAAN_DISTRICT: "大安區",
    Section.NEIHU_DISTRICT: "內湖區",
    Section.SHILIN_DISTRICT: "士林區",
    Section.WENSHAN_DISTRICT: "文山區",
    Section.BEITOU_DISTRICT: "北投區",
    Section.ZHONGSHAN_DISTRICT: "中山區",
    Section.XINYI_DISTRICT: "信義區",
    Section.SONGSHAN_DISTRICT: "松山區",
    Section.WANHUA_DISTRICT: "萬華區",
    Section.ZHONGZHENG_DISTRICT: "中正區",
    Section.DATONG_DISTRICT: "大同區",
    Section.NANGANG_DISTRICT: "南港區",
    # new taipei city
    Section.BANQIAO_DISTRICT: "板橋區",
    Section.XINZHUANG_DISTRICT: "新莊區",
    Section.ZHONGHE_DISTRICT: "中和區",
    Section.SANCHONG_DISTRICT: "三重區",
    Section.XINDIAN_DISTRICT: "新店區",
    Section.TUCHENG_DISTRICT: "土城區",
    Section.YONGHE_DISTRICT: "永和區",
    Section.XIZHI_DISTRICT: "汐止區",
    Section.LUZHOU_DISTRICT: "蘆洲區",
    Section.DANSHUI_DISTRICT: "淡水區",
    Section.SHULIN_DISTRICT: "樹林區",
    Section.LINKOU_DISTRICT: "林口區",
    Section.SANXIA_DISTRICT: "三峽區",
    Section.WUGU_DISTRICT: "五股區",
    Section.YINGGE_DISTRICT: "鶯歌區",
    Section.TAISHAN_DISTRICT: "泰山區",
    Section.BALI_DISTRICT: "八里區",
    Section.RUIFANG_DISTRICT: "瑞芳區",
    Section.SHENKENG_DISTRICT: "深坑區",
    Section.SANZHI_DISTRICT: "三芝區",
    Section.WANLI_DISTRICT: "萬里區",
    Section.JINSHAN_DISTRICT: "金山區",
    Section.GONGLIAO_DISTRICT: "貢寮區",
    Section.SHIMEN_DISTRICT: "石門區",
    Section.SHUANGXI_DISTRICT: "雙溪區",
    Section.SHIDING_DISTRICT: "石碇區",
    Section.PINGLIN_DISTRICT: "坪林區",
    Section.WULAI_DISTRICT: "烏來區",
    Section.PINGXI_DISTRICT: "平溪區",
}


region_sections = {
    Region.TAIPEI_CITY: {
        Section.DAAN_DISTRICT,
        Section.NEIHU_DISTRICT,
        Section.SHILIN_DISTRICT,
        Section.WENSHAN_DISTRICT,
        Section.BEITOU_DISTRICT,
        Section.ZHONGSHAN_DISTRICT,
        Section.XINYI_DISTRICT,
        Section.SONGSHAN_DISTRICT,
        Section.WANHUA_DISTRICT,
        Section.ZHONGZHENG_DISTRICT,
        Section.DATONG_DISTRICT,
        Section.NANGANG_DISTRICT,
    },
    Region.NEW_TAIPEI_CITY: {
        Section.BANQIAO_DISTRICT,
        Section.XINZHUANG_DISTRICT,
        Section.ZHONGHE_DISTRICT,
        Section.SANCHONG_DISTRICT,
        Section.XINDIAN_DISTRICT,
        Section.TUCHENG_DISTRICT,
        Section.YONGHE_DISTRICT,
        Section.XIZHI_DISTRICT,
        Section.LUZHOU_DISTRICT,
        Section.DANSHUI_DISTRICT,
        Section.SHULIN_DISTRICT,
        Section.LINKOU_DISTRICT,
        Section.SANXIA_DISTRICT,
        Section.WUGU_DISTRICT,
        Section.YINGGE_DISTRICT,
        Section.TAISHAN_DISTRICT,
        Section.BALI_DISTRICT,
        Section.RUIFANG_DISTRICT,
        Section.SHENKENG_DISTRICT,
        Section.SANZHI_DISTRICT,
        Section.WANLI_DISTRICT,
        Section.JINSHAN_DISTRICT,
        Section.GONGLIAO_DISTRICT,
        Section.SHIMEN_DISTRICT,
        Section.SHUANGXI_DISTRICT,
        Section.SHIDING_DISTRICT,
        Section.PINGLIN_DISTRICT,
        Section.WULAI_DISTRICT,
        Section.PINGXI_DISTRICT,
    },
}
