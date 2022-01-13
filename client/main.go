
package main

import (
	tls "crypto/tls"
	io "io"
	net "net"
	http "net/http"
	os "os"
	time "time"
	strings "strings"

	websocket "github.com/gorilla/websocket"
	golog "github.com/kmcsr/go-logger"
	ufile "github.com/kmcsr/go-util/file"
	json "github.com/kmcsr/go-util/json"
)

var logger = golog.NewLogger("CLIENT")

var (
	USERNAME string = ""
	PASSWORD string = ""
	REMOTE string = ""
	BRIDGES map[string]string = nil
)

var WsDialer *websocket.Dialer = &websocket.Dialer{
	Proxy:            http.ProxyFromEnvironment,
	HandshakeTimeout: 45 * time.Second,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

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
		USERNAME = obj.GetString("username")
		PASSWORD = obj.GetString("password")
		REMOTE = obj.GetString("remote")
		if REMOTE[len(REMOTE) - 1] != '/' {
			REMOTE += "/"
		}
		BRIDGES = obj.GetStringMap("bridges")
	}
}

func handler(nc net.Conn, remote string){
	defer nc.Close()
	var (
		header http.Header = http.Header{}
		conn *websocket.Conn
		t int
		buf []byte
		err error
	)
	(&http.Request{Header: header}).SetBasicAuth(USERNAME, PASSWORD)
	conn, _, err = WsDialer.Dial(remote, header)
	if err != nil {
		logger.Error("Websocket connect error:", err)
		return
	}
	defer conn.Close()
	go func(){
		defer nc.Close()
		defer conn.Close()
		var (
			rb = make([]byte, 1024 * 128) // 128KB
			n int
			err error
		)
		for {
			n, err = nc.Read(rb)
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
	for {
		t, buf, err = conn.ReadMessage()
		if err != nil {
			return
		}
		if t == websocket.BinaryMessage {
			_, err = nc.Write(buf)
			if err != nil {
				logger.Error("Error on write:", err)
				return
			}
		}
	}
}

func main(){
	count := 0
	trigger := make(chan struct{})
	for local, remot := range BRIDGES {
		svr, err := net.Listen("tcp", local)
		if err != nil {
			logger.Errorf("Cannot listen on \"%s\": %v", local, err)
			return
		}
		logger.Infof("Proxy \"%s\" to \"%s\"", local, remot)
		count++
		host, port := split(remot, ':', true)
		remote := httpToWs(REMOTE + host + "/" + port)
		go func(){
			defer func(){
				count--
				trigger <- struct{}{}
			}()
			var (
				conn net.Conn
				err error
			)
			for {
				conn, err = svr.Accept()
				if err != nil {
					return
				}
				go handler(conn, remote)
			}
		}()
	}
	for count > 0 {
		<-trigger
	}
}

func httpToWs(origin string)(string){
	if strings.HasPrefix(origin, "http") {
		return "ws" + origin[4:]
	}
	return origin
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
