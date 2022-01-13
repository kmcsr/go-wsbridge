
package main

import (
	context "context"
	// tls "crypto/tls"
	sha256 "crypto/sha256"
	hex "encoding/hex"
	fmt "fmt"
	io "io"
	net "net"
	http "net/http"
	os "os"
	signal "os/signal"
	sort "sort"
	strconv "strconv"
	regexp "regexp"
	syscall "syscall"
	time "time"

	websocket "github.com/gorilla/websocket"
	golog "github.com/kmcsr/go-logger"
	ufile "github.com/kmcsr/go-util/file"
	json "github.com/kmcsr/go-util/json"
)

var reg_name *regexp.Regexp = regexp.MustCompile(`^[A-Za-z_-][0-9A-Za-z_-]{1,31}$`)
var logger = golog.NewLogger("SERVER")

var (
	HOST string = ""
	PORT uint16 = 0
	USER_DIR string = ""
	USE_HTTPS bool = false
	CRT_FILE string = ""
	KEY_FILE string = ""
)

func init(){
	{ // read config file
		var fd *os.File
		var err error
		fd, err = os.Open(ufile.JoinPath("config", "config.json"))
		if err != nil {
			panic(err)
		}
		defer fd.Close()
		var obj json.JsonObj
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
}

type ServerHandler struct{
}

func (s *ServerHandler)serve1(res http.ResponseWriter, req *http.Request, host string, port uint16, user *UserData){
	var (
		conn *websocket.Conn
		tg net.Conn
		err error
	)
	conn, err = websocket.Upgrade(res, req, http.Header{}, 0, 0)
	if err != nil {
		return
	}
	tg, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		conn.Close()
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
				if err != io.EOF {
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
	logger.Info("url:", req.RequestURI)
	username, password, _ = req.BasicAuth()
	user = checkUsername(username, password)
	if user == nil {
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
		if !user.CheckHost(host, port) {
			res.WriteHeader(http.StatusUnauthorized)
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
	server := &http.Server{
		Addr: fmt.Sprintf("%s:%d", HOST, PORT),
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
	case <-sigs:
		timeoutCtx, _ := context.WithTimeout(bgcont, 16 * time.Second)
		logger.Warn("Closing server...")
		server.Shutdown(timeoutCtx)
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
	LEVEL_NORMAL = 1
	LEVEL_TRUST  = 9
)

type UserData struct{
	Password string `json:"password"`
	Level int       `json:"level"`
	Hosts []string  `json:"hosts"`
}

func (user *UserData)CheckHost(host string, port int)(ok bool){
	if user.Level <= LEVEL_BANNED {
		return false
	}
	if user.Level >= LEVEL_TRUST {
		return true
	}
	if !strInList(host, sortStrings(user.Hosts)) {
		return false
	}
	return true
}

func checkUsername(username string, password string)(user *UserData){
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
	if user.Password != hex.EncodeToString(pwd[:]) || user.Level < LEVEL_NORMAL {
		return nil
	}
	return
}

func split(s string, b byte, last bool)(string, string){
	if last {
		for i := len(s) - 1; i >= 0; i-- {
			if s[i] == b {
				return s[:i], s[i + 1:]
			}
		}
	}else{
		l := len(s)
		for i := 0; i < l; i++ {
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
