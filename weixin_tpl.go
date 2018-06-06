package wechat

import (
	"bytes"
	"encoding/json"
	"net/http"
)

//设置所属行业https://api.weixin.qq.com/cgi-bin/template/api_set_industry?access_token=ACCESS_TOKEN
//获取设置的行业信息https://api.weixin.qq.com/cgi-bin/template/get_industry?access_token=ACCESS_TOKEN
//获得模板IDhttps://api.weixin.qq.com/cgi-bin/template/api_add_template?access_token=ACCESS_TOKEN
//获取模板列表https://api.weixin.qq.com/cgi-bin/template/get_all_private_template?access_token=ACCESS_TOKEN
//删除模板https://api,weixin.qq.com/cgi-bin/template/del_private_template?access_token=ACCESS_TOKEN
//

//访问地址
const (
	TEMPLATESENDURL = "https://api.weixin.qq.com/cgi-bin/message/template/send"
)

//STTemplateData STTemplateData
type STTemplateData struct {
	Value string `json:"value,omitempty"`
	Color string `json:"color,omitempty"`
}

//STTemplate STTemplate
type STTemplate struct {
	Touser     string                    `json:"touser"`
	Templateid string                    `json:"template_id"`
	URL        string                    `json:"url"`
	Data       map[string]STTemplateData `json:"data,json"`
}

//SendTemplate 发送模板消息https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=ACCESS_TOKEN
func (wx *Wechat) SendTemplate(touser, templateid, url string,
	data map[string]STTemplateData) (string, error) {
	tpl := STTemplate{touser, templateid, url, data}
	rdata, _ := json.Marshal(tpl)
	req, err := http.NewRequest("POST", TEMPLATESENDURL+"?access_token="+
		wx.AccessToken, bytes.NewReader(rdata))
	res, err := wx.requsetJSON(req, 0)
	if err != nil {
		return "", err
	}
	return string(res), nil
}
