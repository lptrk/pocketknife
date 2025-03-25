package main

import (
	"encoding/json"
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

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
}

type TunnelConfig struct {
	Name     string   `json:"name"`
	Server   Endpoint `json:"server"`
	Local    Endpoint `json:"local"`
	Remote   Endpoint `json:"remote"`
	Key      string   `json:"key"`
	Password string   `json:"password"`
}

const configFile = "tunnels.json"

func (e *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func loadTunnels() ([]TunnelConfig, error) {
	file, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []TunnelConfig{}, nil
		}
		return nil, err
	}
	var tunnels []TunnelConfig
	if err := json.Unmarshal(file, &tunnels); err != nil {
		return nil, err
	}
	return tunnels, nil
}

func saveTunnels(tunnels []TunnelConfig) error {
	data, err := json.MarshalIndent(tunnels, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
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

	return endpoint
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

	fmt.Printf("Listening on %s\n", t.Local.String())

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

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(lc, remoteConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(remoteConn, lc)
		done <- struct{}{}
	}()
	<-done
}

func PrivateKeyFile(file string) (ssh.AuthMethod, error) {
	buffer, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return ssh.PublicKeys(key), nil
}

func startTunnel(t TunnelConfig) {
	authMethods := make([]ssh.AuthMethod, 0)
	if t.Key != "" {
		keyAuth, err := PrivateKeyFile(t.Key)
		if err != nil {
			log.Fatalf("Failed to load private key: %v", err)
		}
		authMethods = append(authMethods, keyAuth)
	}
	if t.Password != "" {
		authMethods = append(authMethods, ssh.Password(t.Password))
	}

	config := &ssh.ClientConfig{
		User:            t.Server.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	tunnel := SSHTunnel{
		Local:  &t.Local,
		Server: &t.Server,
		Remote: &t.Remote,
		Config: config,
	}

	log.Printf("Starting tunnel: %s -> %s via %s", t.Local.String(), t.Remote.String(), t.Server.String())
	if err := tunnel.Start(); err != nil {
		log.Fatalf("Failed to start tunnel: %s", err)
	}
}

func main() {
	rootCmd := &cobra.Command{Use: "pocket"}

	tunnelCmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Manage SSH tunnels",
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start an SSH tunnel",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			tunnels, err := loadTunnels()
			if err != nil {
				log.Fatalf("Error loading tunnels: %v", err)
			}
			for _, t := range tunnels {
				if t.Name == name {
					startTunnel(t)
					return
				}
			}
			log.Fatalf("Tunnel with name '%s' not found", name)
		},
	}
	startCmd.Flags().String("name", "", "Name of the tunnel to start")
	startCmd.MarkFlagRequired("name")

	saveCmd := &cobra.Command{
		Use:   "save",
		Short: "Save an SSH tunnel configuration",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			server, _ := cmd.Flags().GetString("server")
			dest, _ := cmd.Flags().GetString("dest")
			local, _ := cmd.Flags().GetString("local")
			keyFile, _ := cmd.Flags().GetString("key")
			password, _ := cmd.Flags().GetString("password")

			serverEndpoint := NewEndpoint(server)
			if serverEndpoint.Port == 0 {
				serverEndpoint.Port = 22
			}

			remoteEndpoint := NewEndpoint(dest)
			if remoteEndpoint.Port == 0 {
				log.Fatal("Remote endpoint port must be specified")
			}

			localEndpoint := NewEndpoint(local)
			if localEndpoint.Host == "" {
				localEndpoint.Host = "localhost"
			}

			tunnel := TunnelConfig{
				Name:     name,
				Server:   *serverEndpoint,
				Remote:   *remoteEndpoint,
				Local:    *localEndpoint,
				Key:      keyFile,
				Password: password,
			}

			tunnels, err := loadTunnels()
			if err != nil {
				log.Fatalf("Error loading tunnels: %v", err)
			}

			// Check for existing tunnel with same name
			for i, t := range tunnels {
				if t.Name == name {
					tunnels[i] = tunnel
					if err := saveTunnels(tunnels); err != nil {
						log.Fatalf("Failed to save tunnels: %v", err)
					}
					log.Println("Tunnel updated successfully")
					return
				}
			}

			tunnels = append(tunnels, tunnel)
			if err := saveTunnels(tunnels); err != nil {
				log.Fatalf("Failed to save tunnels: %v", err)
			}
			log.Println("Tunnel saved successfully")
		},
	}
	saveCmd.Flags().String("name", "", "Name of the tunnel")
	saveCmd.Flags().String("server", "", "SSH server address (user@host:port)")
	saveCmd.Flags().String("dest", "", "Remote destination (host:port)")
	saveCmd.Flags().String("local", "localhost:0", "Local endpoint (host:port)")
	saveCmd.Flags().String("key", "", "Path to private key file")
	saveCmd.Flags().String("password", "", "SSH password")
	saveCmd.MarkFlagRequired("name")
	saveCmd.MarkFlagRequired("server")
	saveCmd.MarkFlagRequired("dest")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List saved SSH tunnels",
		Run: func(cmd *cobra.Command, args []string) {
			tunnels, err := loadTunnels()
			if err != nil {
				log.Fatalf("Error loading tunnels: %v", err)
			}
			for _, t := range tunnels {
				fmt.Printf("%s -> %s (via %s)\n", t.Name, t.Remote.String(), t.Server.String())
			}
		},
	}

	tunnelCmd.AddCommand(startCmd, saveCmd, listCmd)
	rootCmd.AddCommand(tunnelCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
