
func Run() {
	{{ .Shellcode }}
	
	loader.Run(sc)
}
