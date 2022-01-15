
package main

import (
	bufio "bufio"
	context "context"
	// tls "crypto/tls"
	sha256 "crypto/sha256"
	hex "encoding/hex"
	// fmt "fmt"
	io "io"
	net "net"
	http "net/http"
	os "os"
	signal "os/signal"
	sort "sort"
	strconv "strconv"
	strings "strings"
	regexp "regexp"
	syscall "syscall"
	time "time"

	websocket "github.com/gorilla/websocket"
	golog "github.com/kmcsr/go-logger"
	ufile "github.com/kmcsr/go-util/file"
	json "github.com/kmcsr/go-util/json"
)

var reg_name *regexp.Regexp = regexp.MustCompile(`^[A-Za-z_-][0-9A-Za-z_-]{1,31}$`)
var space_re = regexp.MustCompile(`\s+`)
var logger = golog.NewLogger("SERVER")

var (
	HOST string = ""
	PORT uint16 = 0
	USER_DIR string = ""
	USE_HTTPS bool = false
	CRT_FILE string = ""
	KEY_FILE string = ""
	HOSTS *HostMap = NewHostMap()
)

func loadConfig(){
	var (
		fd *os.File
		err error
		obj json.JsonObj
	)
	fd, err = os.Open(ufile.JoinPath("config", "config.json"))
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	obj, err = json.ReadJsonObj(fd)
	if err != nil {
		panic(err)
	}
	HOST = obj.GetStringDefault("host", "0.0.0.0")
	PORT = obj.GetUInt16("port")
	USER_DIR = obj.GetString("users")
	USE_HTTPS = obj.GetBoolDefault("https", false)
	if USE_HTTPS {
		CRT_FILE = obj.GetString("crt_file")
		KEY_FILE = obj.GetString("key_file")
	}
}

func loadHosts(){
	HOSTS = NewHostMap()
	var (
		fd *os.File
		err error
		sc *bufio.Scanner
		ln string
		bf string
		s2 []string
	)
	fd, err = os.Open(ufile.JoinPath("config", "hosts"))
	if err != nil {
		logger.Error("Cannot open file `config/hosts`:", err)
		return
	}
	defer fd.Close()
	sc = bufio.NewScanner(fd)

	for sc.Scan() {
		ln = sc.Text()
		bf, _ = split(ln, '#', false)
		bf = strings.TrimSpace(bf)
		if len(bf) > 0 {
			s2 = space_re.Split(bf, 2)
			if len(s2) < 2 {
				logger.Error("Error syntax at:", ln)
				continue
			}
			HOSTS.add(s2[0], s2[1])
		}
	}
}

type ServerHandler struct{
}

func (s *ServerHandler)serve1(res http.ResponseWriter, req *http.Request, host string, port uint16, user *UserData){
	ip := HOSTS.G(host, port, user)
	if len(ip) == 0 || ip == "!" {
		res.WriteHeader(http.StatusForbidden)
		res.Write(([]byte)("Not authorized host or port"))
		return
	}
	var (
		conn *websocket.Conn
		tg net.Conn
		err error
	)
	tg, err = net.Dial("tcp", ip)
	if err != nil {
		logger.Errorf("Error on connect remote[%s]: %v", ip, err)
		res.WriteHeader(http.StatusUnprocessableEntity)
		res.Write(([]byte)(ip + ":" + err.Error()))
		return
	}
	conn, err = websocket.Upgrade(res, req, http.Header{}, 0, 0)
	if err != nil {
		tg.Close()
		return
	}
	go func(){
		defer conn.Close()
		defer tg.Close()
		var (
			rb = make([]byte, 1024 * 128) // 128KB
			n int
			err error
		)
		for {
			n, err = tg.Read(rb)
			if err != nil {
				if err != io.EOF && !strings.HasSuffix(err.Error(), net.ErrClosed.Error()) {
					logger.Error("Error on read:", err)
				}
				return
			}
			err = conn.WriteMessage(websocket.BinaryMessage, rb[:n])
			if err != nil {
				return
			}
		}
	}()
	go func(){
		defer conn.Close()
		defer tg.Close()
		var (
			t int
			buf []byte
		)
		for {
			t, buf, err = conn.ReadMessage()
			if err != nil {
				return
			}
			if t == websocket.BinaryMessage {
				_, err = tg.Write(buf)
				if err != nil {
					logger.Error("Error on write:", err)
					return
				}
			}
		}
	}()
}

func (s *ServerHandler)ServeHTTP(res http.ResponseWriter, req *http.Request){
	if req.URL.Path == "/" {
		res.WriteHeader(http.StatusOK)
		res.Write(([]byte)("Hello world"))
		return
	}
	var (
		username string
		password string
		user *UserData
		mode string
		path string
		host string
		port int
		err error
	)
	logger.Info("serve url:", req.RequestURI)
	username, password, _ = req.BasicAuth()
	if user = GetUser(username, password); user == nil {
		res.WriteHeader(http.StatusUnauthorized)
		res.Write(([]byte)("Username or password wrong"))
		return
	}
	mode, path = split(req.URL.Path[1:], '/', false)
	switch mode {
	case "1":
		host, path = split(path, '/', true)
		port, err = strconv.Atoi(path)
		if err != nil {
			res.WriteHeader(http.StatusBadRequest)
			res.Write(([]byte)(err.Error()))
			return
		}
		if port > 65535 || port < 0 {
			res.WriteHeader(http.StatusBadRequest)
			res.Write(([]byte)("Port not in range [0, 65536)"))
			return
		}
		if !user.CheckAddress(host, (uint16)(port)) {
			res.WriteHeader(http.StatusForbidden)
			res.Write(([]byte)("Not authorized host or port"))
			return
		}
		s.serve1(res, req, host, (uint16)(port), user)
		return
	case "ping":
		res.WriteHeader(http.StatusOK)
		tm := time.Now()
		json.WriteJson(res, json.JsonObj{
			"status": "ok",
			"t": tm.Unix() * 1000 + tm.UnixNano() / 1000 % 1000,
		})
		return
	}
	res.WriteHeader(http.StatusNotFound)
	res.Write(([]byte)("404 Not Found"))
}

func main(){
	begin:

	loadConfig()
	loadHosts()

	server := &http.Server{
		Addr: fmtAddr(HOST, PORT),
		Handler: &ServerHandler{},
	}

	go func(){
		logger.Infof("Server start at \"%s\"", server.Addr)
		var err error
		if USE_HTTPS {
			err = server.ListenAndServeTLS(CRT_FILE, KEY_FILE)
		}else{
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("Http server error:", err)
		}
	}()

	bgcont := context.Background()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	select {
	case s := <-sigs:
		timeoutCtx, _ := context.WithTimeout(bgcont, 16 * time.Second)
		logger.Warn("Closing server...")
		server.Shutdown(timeoutCtx)
		if s == syscall.SIGHUP {
			logger.Warn("Reloading config...")
			goto begin
		}
	}
}

func comparePwd(a []byte, b []byte)(ok bool){
	ok = true
	l := len(a)
	l2 := len(b)
	if l2 != l {
		ok = false
		if l2 < l {
			l = l2
		}
	}
	for i := 0; i < l; i++ {
		if a[i] != b[i] {
			ok = false
		}
	}
	return
}

const (
	LEVEL_BANNED = -1
	LEVEL_GUEST  = 1
	LEVEL_NORMAL = 3
	LEVEL_ADMIN  = 8
	LEVEL_SUPER  = 9
)

type HostMap struct{
	m map[string]func(string, uint16)(string)
}

func NewHostMap()(*HostMap){
	return &HostMap{
		m: make(map[string]func(string, uint16)(string)),
	}
}

func (m *HostMap)add(key string, v string){
	var f func(host string, port uint16)(ip string) = nil
	if strings.HasPrefix(v, "srv+") {
		v = v[4:]
		f = func(host string, port uint16)(ip string){
			_, s, _ := net.LookupSRV(v, "tcp", host)
			if s != nil && len(s) > 0 {
				host, port = s[0].Target, s[0].Port
			}
			return fmtAddr(host, port)
		}
	}else if v[0] == '!' {
		h, p := split(v[1:], ':', true)
		if h == "" {
			if len(h) > 0 && h[len(h) - 1] == '.' {
				h = h[:len(h) - 1]
			}
			p0, e := strconv.Atoi(p)
			if e == nil {
				f = func(_ string, port uint16)(string){
					if port == (uint16)(p0) { return "!" }; return ""
				}
			}
		}else{
			if h[0] == '*' {
				h = h[1:]
				f = func(host string, _ uint16)(string){
					if strings.HasSuffix(host, h) { return "!" }; return ""
				}
			}else if h[len(h) - 1] == '*' {
				h = h[:len(h) - 1]
				f = func(host string, _ uint16)(string){
					if strings.HasPrefix(host, h) { return "!" }; return ""
				}
			}else{
				f = func(host string, _ uint16)(string){
					if host == h { return "!" }; return ""
				}
			}
		}
	}else{
		h, p := split(v, ':', true)
		if h == "" {
			if len(h) > 0 && h[len(h) - 1] == '.' {
				h = h[:len(h) - 1]
			}
			f = func(host string, _ uint16)(string){
				return host + ":" + p
			}
		}else{
			f = func(_ string, port uint16)(string){
				return fmtAddr(h, port)
			}
		}
	}
	if f != nil {
		m.m[key] = f
	}
}

func (m *HostMap)G(host string, port uint16, user *UserData)(ip string){
	ip = fmtAddr(host, port)
	f, ok := m.m[ip]
	if !ok { return }
	if s := f(host, port); len(s) > 0 {
		if s != "!" || user.Level < LEVEL_SUPER {
			ip = s
		}
	}
	return
}

type UserData struct{
	Password string `json:"password"`
	Level int       `json:"level"`
	Hosts []string  `json:"hosts"`
	Ports []string  `json:"ports"`
}

func (user *UserData)checkHost(host string)(ok bool){
	for _, h := range user.Hosts {
		if h[0] == '*' {
			if strings.HasSuffix(host, h[1:]) {
				return true
			}
		}else{
			if host == h {
				return true
			}
		}
	}
	return false
}

func (user *UserData)CheckAddress(host string, port uint16)(ok bool){
	switch {
	case LEVEL_ADMIN <= user.Level:
		return true
	case LEVEL_NORMAL <= user.Level:
		if user.checkHost(host) {
			return true
		}
		fallthrough
	case LEVEL_GUEST <= user.Level:
		if strInList(fmtAddr(host, port), sortStrings(user.Ports)) {
			return true
		}
		return false
	case LEVEL_BANNED >= user.Level:
		return false
	}
	return false
}

func GetUser(username string, password string)(user *UserData){
	var (
		err error
		fd *os.File
	)
	pwd := sha256.Sum256(([]byte)(password))
	if !reg_name.MatchString(username) {
		return nil
	}
	fd, err = os.Open(ufile.JoinPath(USER_DIR, username + ".json"))
	if err != nil {
		return nil
	}
	defer fd.Close()
	err = json.ReadJson(fd, &user)
	if err != nil {
		return nil
	}
	if user.Level <= LEVEL_BANNED || user.Password != hex.EncodeToString(pwd[:]) {
		return nil
	}
	return
}

func index(s string, b byte)(int){
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func split(s string, b byte, last bool)(string, string){
	if last {
		for i := len(s) - 1; i >= 0; i-- {
			if s[i] == b {
				return s[:i], s[i + 1:]
			}
		}
	}else{
		for i := 0; i < len(s); i++ {
			if s[i] == b {
				return s[:i], s[i + 1:]
			}
		}
	}
	return s, ""
}

func sortStrings(list []string)([]string){
	sort.Strings(list)
	return list
}

func strInList(str string, list []string)(bool){
	i := sort.SearchStrings(list, str)
	return -1 < i && i < len(list) && list[i] == str
}

func fmtAddr(host string, port uint16)(string){
	if len(host) > 0 && host[len(host) - 1] == '.' {
		host = host[:len(host) - 1]
	}
	if index(host, ':') >= 0 {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa((int)(port))
}
