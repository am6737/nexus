package interfaces

type ConnWriter interface {
	Write(p []byte, vpnIP string) (n int, err error)
}
