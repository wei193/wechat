package wechat

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

//基础定义
const (
	Text     = "text"
	Location = "location"
	Image    = "image"
	Link     = "link"
	Event    = "event"
	Music    = "music"
	News     = "news"

	URLGETCALLBACKIP = "https://api.weixin.qq.com/cgi-bin/getcallbackip"
	URLTOKEN         = "https://api.weixin.qq.com/cgi-bin/token"
	URLGETTICKET     = "https://api.weixin.qq.com/cgi-bin/ticket/getticket"
)

//CallbackFun 回调函数
type CallbackFun func(*Wechat, ...interface{}) (interface{}, error)

//JSONError  微信错误
type JSONError struct {
	Errcode int    `json:"errcode"`
	Errmsg  string `json:"errmsg"`
}

//XMLError  微信错误
type XMLError struct {
	ReturnCode string `xml:"return_code"`
	ReturnMsg  string `xml:"return_msg"`
	ResultCode string `xml:"result_code"`
	ErrCode    string `xml:"err_code"`
	ErrCodeDes string `xml:"err_code_des"`
}

//ResAccessToken ResAccessToken
type ResAccessToken struct {
	AccessToken string `json:"access_token"`
	Expiresin   int    `json:"expires_in"`
	Errcode     string `json:"errcode"`
}

//ResUserToken 用户Token
type ResUserToken struct {
	AccessToken string `json:"access_token"`
	Expiresin   int    `json:"expires_in"`
	Openid      string `json:"openid"`
	Scope       string `json:"scope"`
	Errmsg      string `json:"Errmsg"`
}

type resJsTicket struct {
	Errcode   int    `json:"errcode"`
	Ticket    string `json:"ticket"`
	Errmsg    string `json:"errmsg"`
	Expiresin int    `json:"expires_in"`
}

//Wechat 微信接口
type Wechat struct {
	Wxid            string
	Appid           string
	Appsecret       string
	Token           string
	Encodingaeskey  string
	AccessToken     string
	AccessTokenTime int64
	Status          int
	Expiresin       int
	accTokenCount   int
	FunCall         map[string]CallbackFun
	Option          map[string]string
	AutoReply       map[string]map[string]STAutoReply
	JsapiTicket     string
	JsapiTokenTime  int64
	_tlsConfig      *tls.Config
}

//New 新建一个微信对象
func New(Wxid, Appid, Appsecret, Token, Encodingaeskey, AccessToken string,
	AccessTokenTime int64, Status int, Option map[string]string, FunCall map[string]CallbackFun) (*Wechat, error) {

	wx := &Wechat{
		Wxid:            Wxid,
		Token:           Token,
		Appid:           Appid,
		Appsecret:       Appsecret,
		Encodingaeskey:  Encodingaeskey,
		AccessToken:     AccessToken,
		AccessTokenTime: AccessTokenTime,
		Status:          Status,
		Expiresin:       3600,
		FunCall:         FunCall,
		AutoReply:       nil,
		Option:          Option,
	}

	if time.Now().Unix()-wx.AccessTokenTime > 3600 {
		wx.getAccessToken()
	} else {
		wx.checkAccessToken()
	}
	wx.getJsapiTicket()
	go wx.defendToken()
	return wx, nil
}

//微信对象access_token维护
func (wx *Wechat) defendToken() {
	for {
		time.Sleep(1 * time.Minute)
		if time.Now().Unix()-wx.AccessTokenTime > 3600 {
			wx.getAccessToken()
			wx.accTokenCount = 0
		} else {
			wx.checkAccessToken()
		}
		if time.Now().Unix()-wx.JsapiTokenTime > 3600 {
			wx.getJsapiTicket()
		}
	}
}

//获取access_token
func (wx *Wechat) getAccessToken() int {
	if wx.Status == 0 || (time.Now().Unix()-wx.AccessTokenTime < 60 && wx.accTokenCount > 5) {
		return -1
	}

	param := make(map[string]string)
	param["grant_type"] = "client_credential"
	param["appid"] = wx.Appid
	param["secret"] = wx.Appsecret

	req, err := http.NewRequest("GET", Param(URLTOKEN, param), nil)

	resBody, err := wx.requsetJSON(req, -1)
	if err != nil {
		log.Println(err)
		return -1
	}
	log.Println(string(resBody))
	var accToken ResAccessToken
	accToken.Errcode = ""
	err = json.Unmarshal(resBody, &accToken)
	if err != nil {
		log.Println(err)
		return -1
	}
	if accToken.Errcode != "" {
		return -1
	}

	if time.Now().Unix()-wx.AccessTokenTime < 60 {
		wx.accTokenCount++
	} else {
		wx.accTokenCount = 0
	}

	wx.AccessTokenTime = time.Now().Unix() - int64(7200-accToken.Expiresin)
	wx.AccessToken = accToken.AccessToken
	wx.Expiresin = accToken.Expiresin
	if _, ok := wx.FunCall["updatetoken"]; ok {
		wx.FunCall["updatetoken"](wx)
	}
	return 0
}

//检查微信access_token有效性
func (wx *Wechat) checkAccessToken() int {
	req, err := http.NewRequest("GET", URLGETCALLBACKIP+"?access_token="+
		wx.AccessToken, nil)
	_, err = wx.requsetJSON(req, 0)
	if err != nil {
		return 0
	}
	return 1
}

//获取js的jsapi_ticket
func (wx *Wechat) getJsapiTicket() int {
	param := make(map[string]string)
	param["access_token"] = wx.AccessToken
	param["type"] = "jsapi"
	req, err := http.NewRequest("GET", Param(URLGETTICKET, param), nil)

	resBody, err := wx.requsetJSON(req, 0)
	if err != nil {
		log.Println(err)
		return 0
	}
	var tmpTick resJsTicket
	err = json.Unmarshal(resBody, &tmpTick)
	if err != nil {
		log.Println(err)
		return 0
	} else if tmpTick.Errcode == 0 {
		wx.JsapiTokenTime = time.Now().Unix()
		wx.JsapiTicket = tmpTick.Ticket
		if _, ok := wx.FunCall["jsapi_ticket"]; ok {
			log.Println("call jsapi_ticket")
			wx.FunCall["jsapi_ticket"](wx)
		}
		return 1
	}
	return 0
}

//CreateJsSignature 创建jsapi_ticket签名
func (wx *Wechat) CreateJsSignature(url, noncestr string, timestamp int64, data map[string]interface{}) string {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["url"] = url
	data["noncestr"] = noncestr
	data["jsapi_ticket"] = wx.JsapiTicket
	data["timestamp"] = strconv.FormatInt(timestamp, 10)
	return SignSha1(data)
}

//Access Token 失效操作
const (
	TOKENIGNORE   = -1
	TOKENRETURN   = 0
	TOKENCONTINUE = 1
)

//发送微信请求
func (wx *Wechat) requsetJSON(req *http.Request, tflag int) ([]byte, error) {
	if tflag != TOKENIGNORE &&
		time.Now().Unix()-wx.AccessTokenTime > int64(wx.Expiresin) {
		if wx.getAccessToken() != 0 {
			return nil, errors.New("获取ac_token出错")
		}
		if tflag == TOKENRETURN {
			return nil, errors.New("ac_token出错")
		}
	}

	resBody, err := requset(req)
	if err != nil {
		return nil, err
	}
	var errcode JSONError
	err = json.Unmarshal(resBody, &errcode)
	if err == nil && errcode.Errcode != 0 {
		if errcode.Errcode == 40001 {
			go wx.getAccessToken()
		}
		return resBody, errors.New(string(resBody))
	}
	return resBody, nil
}

func (wx *Wechat) requsetXML(req *http.Request, tflag int) ([]byte, error) {
	if tflag != TOKENIGNORE &&
		time.Now().Unix()-wx.AccessTokenTime > int64(wx.Expiresin) {
		if wx.getAccessToken() != 0 {
			return nil, errors.New("获取ac_token出错")
		}
		if tflag == TOKENRETURN {
			return nil, errors.New("ac_token出错")
		}
	}
	resBody, err := requset(req)
	if err != nil {
		return nil, err
	}
	var errcode XMLError
	err = xml.Unmarshal(resBody, &errcode)
	if err != nil ||
		errcode.ReturnCode != "SUCCESS" ||
		errcode.ResultCode != "SUCCESS" ||
		errcode.ErrCode != "" {
		return resBody, errors.New(string(resBody))
	}

	return resBody, nil
}

func requset(req *http.Request) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

//Param 生成请求url参数
func Param(urlBase string, P map[string]string) string {
	for k, v := range P {
		if strings.Index(urlBase, "?") != -1 {
			urlBase += "&"
		} else {
			urlBase += "?"
		}
		urlBase += k
		urlBase += "="
		urlBase += url.QueryEscape(v)
	}
	return urlBase
}

//SignSha1 hash1签名
func SignSha1(data map[string]interface{}) string {
	var keys []string
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	str1 := ""
	for i := range keys {
		val := data[keys[i]]
		var str string
		switch val.(type) {
		case string:
			str = val.(string)
		case bool:
			str = strconv.FormatBool(val.(bool))
		case int:
			str = strconv.Itoa(val.(int))
		case int64:
			str = strconv.FormatInt(val.(int64), 10)
		case []byte:
			str = string(val.([]byte))
		default:
			continue
		}
		if len(str) == 0 {
			continue
		}
		if len(str1) != 0 {
			str1 += "&"
		}
		str1 += keys[i] + "=" + str
	}
	t := sha1.New()
	io.WriteString(t, str1)
	return fmt.Sprintf("%x", t.Sum(nil))
}

//XMLSignMd5 MD5签名
func XMLSignMd5(data interface{}, key string) string {
	k := reflect.TypeOf(data)
	v := reflect.ValueOf(data)
	var keys []string
	m := make(map[string]interface{})
	for i := 0; i < k.NumField(); i++ {
		chKey := k.Field(i).Tag.Get("xml")
		tmpStr := strings.Split(chKey, ",")
		keys = append(keys, tmpStr[0])
		if len(tmpStr) > 1 && tmpStr[1] == "omitempty" && IsEmptyValue(v.Field(i)) {
			continue
		}
		m[tmpStr[0]] = v.Field(i).Interface()
	}
	sort.Strings(keys)
	str1 := ""
	for i := range keys {
		val := m[keys[i]]
		var str string
		switch val.(type) {
		case string:
			str = val.(string)
		case bool:
			str = strconv.FormatBool(val.(bool))
		case int:
			str = strconv.Itoa(val.(int))
		case int64:
			str = strconv.FormatInt(val.(int64), 10)
		case []byte:
			str = string(val.([]byte))
		default:
			continue
		}
		if len(str) == 0 {
			continue
		}
		if len(str1) != 0 {
			str1 += "&"
		}
		str1 += keys[i] + "=" + str
	}
	str1 += "&key=" + key
	t := md5.New()
	io.WriteString(t, str1)
	return fmt.Sprintf("%X", t.Sum(nil))
}

//CheckSignMd5 检查数据的MD5是否正确
func CheckSignMd5(data interface{}, signName, key string) (string, bool) {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Map {
		return "", false
	}
	var keys []string
	var sign string
	var signStr string

	m := make(map[string]string)
	for _, t := range val.MapKeys() {
		k := fmt.Sprint(t.Interface())
		if k == signName {
			sign = fmt.Sprint(val.MapIndex(t).Interface())
		}
		keys = append(keys, k)
		m[k] = fmt.Sprint(val.MapIndex(t).Interface())
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i != 0 {
			signStr += "&"
		}
		signStr += k + "=" + m[k]
	}
	signStr += "&key=" + key
	tMd5 := md5.New()
	io.WriteString(tMd5, signStr)
	return fmt.Sprintf("%X", tMd5.Sum(nil)), fmt.Sprintf("%X", tMd5.Sum(nil)) == sign
}

// IsEmptyValue 判断值是否为空
func IsEmptyValue(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

//DecodeRequest 解析请求
func DecodeRequest(data []byte) (req *STMsgRequest, err error) {
	req = &STMsgRequest{}
	if err = xml.Unmarshal(data, req); err != nil {
		return
	}
	req.CreateTime *= time.Second
	return
}

//RandomStr 随机字符串
/*Random = 0  // 纯数字
Random = 1  // 小写字母
Random = 2  // 大写字母
Random   = 3  // 数字、大小写字母*/
func RandomStr(size int, Random int) string {
	iRandom, Randoms, result := Random, [][]int{[]int{10, 48}, []int{26, 97}, []int{26, 65}}, make([]byte, size)
	iAll := Random > 2 || Random < 0
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < size; i++ {
		if iAll { // random ikind
			iRandom = rand.Intn(3)
		}
		scope, base := Randoms[iRandom][0], Randoms[iRandom][1]
		result[i] = uint8(base + rand.Intn(scope))
	}
	return string(result)
}

func (wx *Wechat) getTLSConfig() (*tls.Config, error) {
	if wx._tlsConfig != nil {
		return wx._tlsConfig, nil
	}
	cert, err := tls.LoadX509KeyPair(wx.Option["CertPath"], wx.Option["KeyPath"])
	if err != nil {
		return nil, err
	}

	caData, err := ioutil.ReadFile(wx.Option["CaPath"])
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caData)

	wx._tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}
	return wx._tlsConfig, nil
}

//httpsPost  HttpsPost请求
func (wx *Wechat) httpsPost(url string, xmlContent []byte, ContentType string) (*http.Response, error) {
	tlsConfig, err := wx.getTLSConfig()
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}
	return client.Post(url,
		ContentType,
		bytes.NewBuffer(xmlContent))
}
