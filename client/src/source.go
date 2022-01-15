
package wsbridge_client

import (
	tls "crypto/tls"
	io "io"
	net "net"
	http "net/http"
	time "time"
	strings "strings"

	websocket "github.com/gorilla/websocket"
	golog "github.com/kmcsr/go-logger"
)

var logger = golog.NewLogger("CLIENT")

var WsDialer *websocket.Dialer = &websocket.Dialer{
	Proxy:            http.ProxyFromEnvironment,
	HandshakeTimeout: 45 * time.Second,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

type User struct{
	Username string
	Password string
}

func NewUser(username string, password string)(*User){
	return &User{
		Username: username,
		Password: password,
	}
}

func (u *User)Handler(nc net.Conn, remote string){
	defer nc.Close()
	var (
		header http.Header = http.Header{}
		res *http.Response
		conn *websocket.Conn
		t int
		buf []byte
		err error
	)
	(&http.Request{Header: header}).SetBasicAuth(u.Username, u.Password)
	conn, res, err = WsDialer.Dial(httpToWs(remote), header)
	if err != nil {
		logger.Errorf("Websocket response: status=%d; url=%s", res.StatusCode, remote)
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

func httpToWs(origin string)(string){
	if strings.HasPrefix(origin, "http") {
		return "ws" + origin[4:]
	}
	return origin
}
