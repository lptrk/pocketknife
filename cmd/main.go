package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// ##################################
// ###        SSH-TUNNELER        ###
// ##################################

type Endpoint struct {
	Host string
	Port int
	User string
}

func NewEndpoint(h string) *Endpoint {
	endpoint := &Endpoint{Host: h}

	if parts := strings.Split(endpoint.Host, "@"); len(parts) > 1 {
		endpoint.User = parts[0]
		endpoint.Host = parts[1]
	}

	if parts := strings.Split(endpoint.Host, ":"); len(parts) > 1 {
		endpoint.Host = parts[0]
		endpoint.Port, _ = strconv.Atoi(parts[1])
	}

	if endpoint.Port == 0 {
		endpoint.Port = 22
	}

	return endpoint
}

func (e *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

type SSHTunnel struct {
	Local  *Endpoint
	Server *Endpoint
	Remote *Endpoint
	Config *ssh.ClientConfig
}

func (t *SSHTunnel) Start() error {
	listener, err := net.Listen("tcp", t.Local.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	t.Local.Port = listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("Listening on localhost:%d\n", t.Local.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go t.forward(conn)
	}
}

func (t *SSHTunnel) forward(lc net.Conn) {
	serverConn, err := ssh.Dial("tcp", t.Server.String(), t.Config)
	if err != nil {
		log.Printf("Server dial error: %s", err)
		return
	}
	defer serverConn.Close()

	remoteConn, err := serverConn.Dial("tcp", t.Remote.String())
	if err != nil {
		log.Printf("Remote dial error: %s", err)
		return
	}
	defer remoteConn.Close()

	go io.Copy(lc, remoteConn)
	go io.Copy(remoteConn, lc)
}

func PrivateKeyFile(file string) ssh.AuthMethod {
	buffer, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("Failed to read private key file: %s", err)
	}
	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
	}
	return ssh.PublicKeys(key)
}

func main() {
	rootCmd := &cobra.Command{Use: "pocket"}

	tunnelCmd := &cobra.Command{
		Use:   "--tunnel",
		Short: "Start an SSH tunnel",
		Run: func(cmd *cobra.Command, args []string) {
			server, _ := cmd.Flags().GetString("server")
			dest, _ := cmd.Flags().GetString("dest")
			keyFile, _ := cmd.Flags().GetString("key")
			password, _ := cmd.Flags().GetString("password")

			if server == "" || dest == "" {
				log.Fatal("Usage: pocket --tunnel --server user@host:port --dest host:port [--key path] [--password pass]")
			}

			var authMethod ssh.AuthMethod
			if keyFile != "" {
				authMethod = PrivateKeyFile(keyFile)
			} else if password != "" {
				authMethod = ssh.Password(password)
			} else {
				log.Fatal("Either private key or password must be provided")
			}

			serverEndpoint := NewEndpoint(server)

			tunnel := &SSHTunnel{
				Local:  NewEndpoint("localhost:0"),
				Server: serverEndpoint,
				Remote: NewEndpoint(dest),
				Config: &ssh.ClientConfig{
					User:            serverEndpoint.User,
					Auth:            []ssh.AuthMethod{authMethod},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				},
			}

			log.Println("Starting SSH tunnel...")
			if err := tunnel.Start(); err != nil {
				log.Fatalf("Tunnel failed: %s", err)
			}
		},
	}

	tunnelCmd.Flags().String("server", "", "SSH Server (user@host:port)")
	tunnelCmd.Flags().String("dest", "", "Remote destination (host:port)")
	tunnelCmd.Flags().String("key", "", "Path to private key file (optional)")
	tunnelCmd.Flags().String("password", "", "SSH password (optional)")

	rootCmd.AddCommand(tunnelCmd)
	rootCmd.Execute()
}
