
package main

import (
	net "net"
	os "os"

	golog "github.com/kmcsr/go-logger"
	ufile "github.com/kmcsr/go-util/file"
	json "github.com/kmcsr/go-util/json"
	. "github.com/kmcsr/go-wsbridge/client/src"
)

var logger = golog.NewLogger("CLIENT")

var (
	USER *User = nil
	REMOTE string = ""
	BRIDGES map[string]string = nil
)

func readConfig(){
	var fd *os.File
	var err error
	fd, err = os.Open(ufile.JoinPath("config", "client.json"))
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	var obj json.JsonObj
	obj, err = json.ReadJsonObj(fd)
	if err != nil {
		panic(err)
	}
	USER = NewUser(obj.GetString("username"), obj.GetString("password"))
	REMOTE = obj.GetString("remote")
	if REMOTE[len(REMOTE) - 1] != '/' {
		REMOTE += "/"
	}
	BRIDGES = obj.GetStringMap("bridges")
}

func main(){
	readConfig()

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
		remote := REMOTE + "1/" + host + "/" + port
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
					logger.Error("Error on accept connection:", err)
					return
				}
				go USER.Handler(conn, remote)
			}
		}()
	}
	for count > 0 {
		<-trigger
	}
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
