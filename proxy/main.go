
package main

import (
	fmt "fmt"
	io "io"
	net "net"
	os "os"
	strconv "strconv"

	golog "github.com/kmcsr/go-logger"
	ufile "github.com/kmcsr/go-util/file"
	json "github.com/kmcsr/go-util/json"
	. "github.com/kmcsr/go-wsbridge/client/src"
)

var logger = golog.NewLogger("PROXY")

var (
	HOST string = ""
	PORT uint16 = 0
	USER *User = nil
	REMOTE string = ""
)

func loadProxyConfig(){
	var (
		fd *os.File
		err error
		obj json.JsonObj
	)
	fd, err = os.Open(ufile.JoinPath("config", "proxy.json"))
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
}

func loadClientConfig(){
	var (
		fd *os.File
		err error
		obj json.JsonObj
	)
	fd, err = os.Open(ufile.JoinPath("config", "client.json"))
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	obj, err = json.ReadJsonObj(fd)
	if err != nil {
		panic(err)
	}
	USER = NewUser(obj.GetString("username"), obj.GetString("password"))
	REMOTE = obj.GetString("remote")
	if REMOTE[len(REMOTE) - 1] != '/' {
		REMOTE += "/"
	}
}

type ProxyHandler struct{
}

func (p *ProxyHandler)auth(conn net.Conn)(err error){
	var (
		b byte
		buf []byte
	)
	b, err = readByte(conn)
	if err != nil { return }
	if b != 0x05 {
		return fmt.Errorf("Unsupported version %x", b)
	}
	b, err = readByte(conn)
	if err != nil { return }
	buf = make([]byte, (int)(b))
	_, err = io.ReadFull(conn, buf)
	if err != nil { return }

	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil { return }

	return nil
}

func (p *ProxyHandler)connect(conn net.Conn)(host string, port uint16, err error){
	var (
		b byte
		l byte
		buf []byte
	)
	b, err = readByte(conn)
	if err != nil { return }
	if b != 0x05 {
		err = fmt.Errorf("Wrong version %x", b)
		return
	}
	b, err = readByte(conn)
	if err != nil { return }
	if b != 0x01 {
		err = fmt.Errorf("Wrong connect type %x", b)
		return
	}
	// before skip RSV
	_, err = readByte(conn)
	if err != nil { return }
	// after skip RSV
	b, err = readByte(conn)
	if err != nil { return }
	switch b {
	case 0x01:
		buf = make([]byte, net.IPv4len)
		_, err = io.ReadFull(conn, buf)
		if err != nil { return }
		host = ((net.IP)(buf)).String()
	case 0x03:
		l, err = readByte(conn)
		if err != nil { return }
		buf = make([]byte, (int)(l))
		_, err = io.ReadFull(conn, buf)
		if err != nil { return }
		host = (string)(buf)
	case 0x04:
		err = fmt.Errorf("Not support IPv6 now")
		return
		// buf = make([]byte, net.IPv6len)
		// _, err = io.ReadFull(conn, buf)
		// if err != nil { return }
		// host = ((net.IP)(buf)).String()
	default:
		err = fmt.Errorf("Unsupported addr type %x", b)
		return
	}
	buf = make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil { return }
	port = (((uint16)(buf[0])) << 8) | ((uint16)(buf[1]))
	return
}

func (p *ProxyHandler)serve(conn net.Conn){
	defer conn.Close()
	var (
		err error
		host string
		port uint16
	)

	if err = p.auth(conn); err != nil {
		logger.Warnf("auth[%s] error: %v", conn.RemoteAddr().String(), err)
		return
	}

	host, port, err = p.connect(conn)
	if err != nil {
		logger.Error("connect error:", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	remote := REMOTE + "1/" + host + "/" + strconv.Itoa((int)(port))
	// logger.Infof("serve %s -> %s", conn.RemoteAddr().String(), remote)
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		logger.Error("connect error:", err)
		return
	}
	USER.Handler(conn, remote)
}

func main(){
	loadProxyConfig()
	loadClientConfig()
	handler := &ProxyHandler{}

	addr := fmtAddr(HOST, PORT)

	server, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("Error on start proxy:", err)
		panic(err)
		return
	}
	logger.Infof("Proxy start at \"socks5://%s\"", addr)
	for {
		conn, err := server.Accept()
		if err != nil {
			logger.Error("Error on accept connection:", err)
			panic(err)
			return
		}
		go handler.serve(conn)
	}
}

func readByte(r io.Reader)(b byte, err error){
	if br, ok := r.(io.ByteReader); ok {
		return br.ReadByte()
	}
	var f [1]byte
	_, err = r.Read(f[:])
	if err != nil { return }
	return f[0], nil
}

func fmtAddr(host string, port uint16)(string){
	if len(host) > 0 && host[len(host) - 1] == '.' {
		host = host[:len(host) - 1]
	}
	return host + ":" + strconv.Itoa((int)(port))
}
