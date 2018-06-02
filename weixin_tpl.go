package wechat

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"github.com/astaxie/beego"
)

//设置所属行业https://api.weixin.qq.com/cgi-bin/template/api_set_industry?access_token=ACCESS_TOKEN
//获取设置的行业信息https://api.weixin.qq.com/cgi-bin/template/get_industry?access_token=ACCESS_TOKEN
//获得模板IDhttps://api.weixin.qq.com/cgi-bin/template/api_add_template?access_token=ACCESS_TOKEN
//获取模板列表https://api.weixin.qq.com/cgi-bin/template/get_all_private_template?access_token=ACCESS_TOKEN
//删除模板https://api,weixin.qq.com/cgi-bin/template/del_private_template?access_token=ACCESS_TOKEN
//

//STTemplateData STTemplateData
type STTemplateData struct {
	Value string `json:"value,omitempty"`
	Color string `json:"color,omitempty"`
}

//STTemplate STTemplate
type STTemplate struct {
	Touser     string      `json:"touser"`
	Templateid string      `json:"template_id"`
	URL        string      `json:"url"`
	Data       interface{} `json:"data,json"`
}

//SendTemplate 发送模板消息https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=ACCESS_TOKEN
func (wx *Wechat) SendTemplate(touser, templateid, url string, data map[string]STTemplateData) int {

	t := STTemplate{touser, templateid, url, data}
	d, _ := json.Marshal(t)

	req, err := http.NewRequest("POST", "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token="+
		wx.AccessToken, bytes.NewReader(d))
	res, err := wx.requsetJSON(req, 0)
	beego.Info(string(res))
	if err != nil {
		log.Println(err)
		return 0
	}
	return 1
}
