/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server SSH KeyGen
 * File Name    : main.go
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2025-09-30 00:19:53
 * Description  : Interactive SSH key generation tool with progress bar and overwrite confirmation
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

const (
	padding  = 2
	maxWidth = 80
)

// Application information
const (
	AppName    = "Abdal 4iProto Server SSH KeyGen"
	AppAuthor  = "Ebrahim Shafiei (EbraSha)"
	AppVersion = "3.0"
	AppTitle   = AppName + " By " + AppAuthor
)

// Algorithm types
const (
	AlgorithmRSA    = "RSA"
	AlgorithmED25519 = "ED25519"
	AlgorithmECDSA  = "ECDSA"
)

// Algorithm information
type AlgorithmInfo struct {
	Name        string
	Description string
	KeySizes    []int
	DefaultSize int
}

var algorithms = []AlgorithmInfo{
	{
		Name:        AlgorithmRSA,
		Description: "RSA - Rivest-Shamir-Adleman (Most compatible)",
		KeySizes:    []int{2048, 3072, 4096, 8192},
		DefaultSize: 4096,
	},
	{
		Name:        AlgorithmED25519,
		Description: "ED25519 - Edwards-curve Digital Signature Algorithm (Modern, Fast)",
		KeySizes:    []int{256}, // Fixed size
		DefaultSize: 256,
	},
	{
		Name:        AlgorithmECDSA,
		Description: "ECDSA - Elliptic Curve Digital Signature Algorithm (Modern, Efficient)",
		KeySizes:    []int{256, 384, 521}, // P-256, P-384, P-521
		DefaultSize: 256,
	},
}

var (
	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#626262")).Render
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575")).
			Bold(true).
			Margin(1, 0)
	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575")).
			Bold(true)
	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5F87")).
			Bold(true)
	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFA500")).
			Bold(true)
)

// Key generation messages
type keyGenStartMsg struct{}
type keyGenCompleteMsg struct {
	privatePath, publicPath string
	comment                 string
}
type keyGenErrorMsg struct {
	err error
}

// Step completion messages
type keyGenStep1CompleteMsg struct {
	priv interface{} // Can be *rsa.PrivateKey, ed25519.PrivateKey, or *ecdsa.PrivateKey
}
type keyGenStep2CompleteMsg struct {
	privPEM []byte
}
type keyGenStep3CompleteMsg struct {
	pubKey []byte
}
type keyGenStep4CompleteMsg struct{}

// Confirmation messages
type confirmOverwriteMsg struct {
	privatePath, publicPath string
}
type overwriteConfirmedMsg struct{}
type overwriteCancelledMsg struct{}

// Success message
type showSuccessMsg struct{}

// Algorithm selection message
type algorithmSelectedMsg struct {
	algorithm string
	keySize   int
}

// Model for the interactive application
type model struct {
	progress     progress.Model
	state        string // "algorithm_selection", "confirm", "generating", "complete", "error"
	message      string
	privatePath  string
	publicPath   string
	comment      string
	algorithm    string // "RSA", "ED25519", "ECDSA"
	bits         int
	force        bool
	width        int
	height       int
	selectedIdx  int // Selected algorithm index
	// Intermediate data for step-by-step generation
	priv         interface{} // Can be *rsa.PrivateKey, ed25519.PrivateKey, or *ecdsa.PrivateKey
	privPEM      []byte
	pubKey       []byte
}

// generateRSAKey generates an RSA private key of the given bit size.
func generateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// generateED25519Key generates an ED25519 private key.
func generateED25519Key() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// generateECDSAKey generates an ECDSA private key for the given curve.
func generateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// getECDSACurve returns the elliptic curve for the given key size.
func getECDSACurve(keySize int) (elliptic.Curve, error) {
	switch keySize {
	case 256:
		return elliptic.P256(), nil
	case 384:
		return elliptic.P384(), nil
	case 521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA key size: %d (supported: 256, 384, 521)", keySize)
	}
}

// encodePrivateKeyToPEM encodes private key to PEM format based on algorithm.
func encodePrivateKeyToPEM(priv interface{}, algorithm string) ([]byte, error) {
	switch algorithm {
	case AlgorithmRSA:
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA private key")
		}
		privBytes := x509.MarshalPKCS1PrivateKey(rsaPriv)
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		}
		return pem.EncodeToMemory(block), nil

	case AlgorithmED25519:
		edPriv, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid ED25519 private key")
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(edPriv)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		}
		return pem.EncodeToMemory(block), nil

	case AlgorithmECDSA:
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid ECDSA private key")
		}
		privBytes, err := x509.MarshalECPrivateKey(ecdsaPriv)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		}
		return pem.EncodeToMemory(block), nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// publicKeySSHPublicKey returns the OpenSSH authorized_keys format for the public key.
func publicKeySSHPublicKey(priv interface{}, algorithm, comment string) ([]byte, error) {
	var pubKey ssh.PublicKey
	var err error

	switch algorithm {
	case AlgorithmRSA:
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA private key")
		}
		pubKey, err = ssh.NewPublicKey(&rsaPriv.PublicKey)
		if err != nil {
			return nil, err
		}

	case AlgorithmED25519:
		edPriv, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid ED25519 private key")
		}
		pubKey, err = ssh.NewPublicKey(edPriv.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}

	case AlgorithmECDSA:
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid ECDSA private key")
		}
		pubKey, err = ssh.NewPublicKey(&ecdsaPriv.PublicKey)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// MarshalAuthorizedKey returns the []byte like: "ssh-rsa AAAAB3NzaC1yc2E... comment\n"
	authorized := ssh.MarshalAuthorizedKey(pubKey)
	if comment != "" {
		// Replace trailing newline with space+comment+newline
		// Note: MarshalAuthorizedKey leaves a trailing newline.
		if len(authorized) > 0 && authorized[len(authorized)-1] == '\n' {
			authorized = authorized[:len(authorized)-1]
		}
		authorized = append(authorized, ' ')
		authorized = append(authorized, []byte(comment)...)
		authorized = append(authorized, '\n')
	}
	return authorized, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	// create temp file in same dir
	tmp, err := os.CreateTemp(dir, "tmpkey-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Commands for key generation
func startKeyGeneration() tea.Cmd {
	return func() tea.Msg {
		return keyGenStartMsg{}
	}
}




// Key generation process
func keyGenerationProcess(m model) tea.Cmd {
	return func() tea.Msg {
		// Step 1: Generate key based on algorithm
		time.Sleep(500 * time.Millisecond)
		var priv interface{}
		var err error

		switch m.algorithm {
		case AlgorithmRSA:
			priv, err = generateRSAKey(m.bits)
		case AlgorithmED25519:
			priv, err = generateED25519Key()
		case AlgorithmECDSA:
			curve, err := getECDSACurve(m.bits)
			if err != nil {
				return keyGenErrorMsg{err: err}
			}
			priv, err = generateECDSAKey(curve)
		default:
			return keyGenErrorMsg{err: fmt.Errorf("unsupported algorithm: %s", m.algorithm)}
		}

		if err != nil {
			return keyGenErrorMsg{err: err}
		}

		// Step 2: Encode private key
		time.Sleep(300 * time.Millisecond)
		privPEM, err := encodePrivateKeyToPEM(priv, m.algorithm)
		if err != nil {
			return keyGenErrorMsg{err: err}
		}

		// Step 3: Encode public key
		time.Sleep(300 * time.Millisecond)
		pubKey, err := publicKeySSHPublicKey(priv, m.algorithm, m.comment)
		if err != nil {
			return keyGenErrorMsg{err: err}
		}

		// Step 4: Write private key
		time.Sleep(400 * time.Millisecond)
		if err := writeFileAtomic(m.privatePath, privPEM, 0o600); err != nil {
			return keyGenErrorMsg{err: err}
		}

		// Step 5: Write public key
		time.Sleep(400 * time.Millisecond)
		if err := writeFileAtomic(m.publicPath, pubKey, 0o644); err != nil {
			// try to remove private if public write fails
			_ = os.Remove(m.privatePath)
			return keyGenErrorMsg{err: err}
		}

		return keyGenCompleteMsg{
			privatePath: m.privatePath,
			publicPath:  m.publicPath,
			comment:     m.comment,
		}
	}
}

// Step-by-step key generation with progress updates
func keyGenerationStep1(m model) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(500 * time.Millisecond)
		var priv interface{}
		var err error

		switch m.algorithm {
		case AlgorithmRSA:
			priv, err = generateRSAKey(m.bits)
		case AlgorithmED25519:
			priv, err = generateED25519Key()
		case AlgorithmECDSA:
			curve, err := getECDSACurve(m.bits)
			if err != nil {
				return keyGenErrorMsg{err: err}
			}
			priv, err = generateECDSAKey(curve)
		default:
			return keyGenErrorMsg{err: fmt.Errorf("unsupported algorithm: %s", m.algorithm)}
		}

		if err != nil {
			return keyGenErrorMsg{err: err}
		}
		return keyGenStep1CompleteMsg{priv: priv}
	}
}

func keyGenerationStep2(priv interface{}, m model) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(300 * time.Millisecond)
		privPEM, err := encodePrivateKeyToPEM(priv, m.algorithm)
		if err != nil {
			return keyGenErrorMsg{err: err}
		}
		return keyGenStep2CompleteMsg{privPEM: privPEM}
	}
}

func keyGenerationStep3(priv interface{}, m model) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(300 * time.Millisecond)
		pubKey, err := publicKeySSHPublicKey(priv, m.algorithm, m.comment)
		if err != nil {
			return keyGenErrorMsg{err: err}
		}
		return keyGenStep3CompleteMsg{pubKey: pubKey}
	}
}

func keyGenerationStep4(privPEM []byte, m model) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(400 * time.Millisecond)
		if err := writeFileAtomic(m.privatePath, privPEM, 0o600); err != nil {
			return keyGenErrorMsg{err: err}
		}
		return keyGenStep4CompleteMsg{}
	}
}

func keyGenerationStep5(pubKey []byte, m model) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(400 * time.Millisecond)
		if err := writeFileAtomic(m.publicPath, pubKey, 0o644); err != nil {
			// try to remove private if public write fails
			_ = os.Remove(m.privatePath)
			return keyGenErrorMsg{err: err}
		}
		return keyGenCompleteMsg{
			privatePath: m.privatePath,
			publicPath:  m.publicPath,
			comment:     m.comment,
		}
	}
}

// Progress update command
func progressUpdateCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return progress.FrameMsg{}
	})
}


// Initialize the model
func (m model) Init() tea.Cmd {
	if m.state == "confirm" {
		return nil
	}
	if m.state == "algorithm_selection" {
		return nil
	}
	if m.algorithm == "" {
		// Start with algorithm selection
		m.state = "algorithm_selection"
		return nil
	}
	return startKeyGeneration()
}

// Update the model based on messages
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case "algorithm_selection":
			switch msg.String() {
			case "up", "k":
				if m.selectedIdx > 0 {
					m.selectedIdx--
				}
				return m, nil
			case "down", "j":
				if m.selectedIdx < len(algorithms)-1 {
					m.selectedIdx++
				}
				return m, nil
			case "enter", " ":
				// Algorithm selected
				selectedAlg := algorithms[m.selectedIdx]
				m.algorithm = selectedAlg.Name
				m.bits = selectedAlg.DefaultSize
				// Update file names based on algorithm
				switch m.algorithm {
				case AlgorithmED25519:
					m.privatePath = "id_ed25519"
					m.publicPath = "id_ed25519.pub"
				case AlgorithmECDSA:
					m.privatePath = "id_ecdsa"
					m.publicPath = "id_ecdsa.pub"
				default: // RSA
					m.privatePath = "id_rsa"
					m.publicPath = "id_rsa.pub"
				}
				// Check if files exist
				filesExist, _ := checkExistingFiles(m.privatePath, m.publicPath)
				if filesExist {
					m.state = "confirm"
				} else {
					m.state = "generating"
					return m, tea.Batch(
						keyGenerationStep1(m),
						progressUpdateCmd(),
					)
				}
				return m, nil
			case "q", "Q", "ctrl+c":
				return m, tea.Quit
			}
		case "confirm":
			switch msg.String() {
			case "y", "Y":
				return m, tea.Batch(
					func() tea.Msg { return overwriteConfirmedMsg{} },
					startKeyGeneration(),
				)
			case "n", "N", "q", "Q", "ctrl+c":
				return m, tea.Quit
			}
		case "complete":
			// Wait for any key to exit
			return m, tea.Quit
		case "error":
			// Wait for any key to exit
			return m, tea.Quit
		}
		return m, nil

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - padding*2 - 4
		if m.progress.Width > maxWidth {
			m.progress.Width = maxWidth
		}
		return m, nil

	case confirmOverwriteMsg:
		m.state = "confirm"
		m.privatePath = msg.privatePath
		m.publicPath = msg.publicPath
		return m, nil

	case overwriteConfirmedMsg:
		m.state = "generating"
		return m, tea.Batch(
			keyGenerationStep1(m),
			progressUpdateCmd(),
		)

	case keyGenStartMsg:
		m.state = "generating"
		m.message = "Starting key generation..."
		return m, tea.Batch(
			keyGenerationStep1(m),
			progressUpdateCmd(),
		)


	case keyGenStep1CompleteMsg:
		m.priv = msg.priv
		algName := m.algorithm
		if m.algorithm == AlgorithmECDSA {
			algName = fmt.Sprintf("%s P-%d", m.algorithm, m.bits)
		}
		m.message = fmt.Sprintf("%s key generated, encoding private key...", algName)
		m.progress.SetPercent(0.2)
		return m, tea.Batch(
			keyGenerationStep2(m.priv, m),
			progressUpdateCmd(),
		)

	case keyGenStep2CompleteMsg:
		m.privPEM = msg.privPEM
		m.message = "Private key encoded, generating public key..."
		m.progress.SetPercent(0.4)
		return m, tea.Batch(
			keyGenerationStep3(m.priv, m),
			progressUpdateCmd(),
		)

	case keyGenStep3CompleteMsg:
		m.pubKey = msg.pubKey
		m.message = "Public key generated, writing private key..."
		m.progress.SetPercent(0.6)
		return m, tea.Batch(
			keyGenerationStep4(m.privPEM, m),
			progressUpdateCmd(),
		)

	case keyGenStep4CompleteMsg:
		m.message = "Private key written, writing public key..."
		m.progress.SetPercent(0.8)
		return m, tea.Batch(
			keyGenerationStep5(m.pubKey, m),
			progressUpdateCmd(),
		)

	case keyGenCompleteMsg:
		m.state = "progress_complete"
		m.message = "Finalizing key generation..."
		m.privatePath = msg.privatePath
		m.publicPath = msg.publicPath
		m.comment = msg.comment
		// Set progress to 100%
		cmd := m.progress.SetPercent(1.0)
		// Wait 2 seconds before showing success message
		return m, tea.Batch(
			cmd,
			tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
				return showSuccessMsg{}
			}),
			progressUpdateCmd(),
		)

	case showSuccessMsg:
		m.state = "complete"
		// Stop progress updates
		return m, nil

	case keyGenErrorMsg:
		m.state = "error"
		m.message = fmt.Sprintf("Error: %v", msg.err)
		return m, nil

	// FrameMsg is sent when the progress bar wants to animate itself
	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		// Continue progress updates if we're still generating or progress is complete
		if m.state == "generating" || m.state == "progress_complete" {
			return m, tea.Batch(cmd, progressUpdateCmd())
		}
		return m, cmd

	default:
		return m, nil
	}
}

// Render the view
func (m model) View() string {
	pad := strings.Repeat(" ", padding)
	
	switch m.state {
	case "algorithm_selection":
		view := "\n" +
			pad + titleStyle.Render(AppTitle) + "\n" +
			pad + fmt.Sprintf("Version %s", AppVersion) + "\n\n" +
			pad + "Select encryption algorithm:\n\n"

		for i, alg := range algorithms {
			prefix := "  "
			if i == m.selectedIdx {
				prefix = "▶ "
			}
			view += pad + prefix + fmt.Sprintf(" %s - %s", alg.Name, alg.Description) + "\n"
		}

		view += "\n" + pad + helpStyle("Use ↑/↓ or j/k to navigate, Enter to select, q to quit")
		return view

	case "confirm":
		return "\n" +
			pad + titleStyle.Render(AppTitle) + "\n\n" +
			pad + warningStyle.Render("⚠️  Files already exist:") + "\n" +
			pad + fmt.Sprintf("   Private key: %s", m.privatePath) + "\n" +
			pad + fmt.Sprintf("   Public key:  %s", m.publicPath) + "\n\n" +
			pad + "Do you want to overwrite these files? (y/N): " + "\n\n" +
			pad + helpStyle("Press 'y' to overwrite, 'n' or 'q' to cancel")

	case "generating":
		algDesc := fmt.Sprintf("%s key", m.algorithm)
		if m.algorithm == AlgorithmRSA {
			algDesc = fmt.Sprintf("%d-bit %s key", m.bits, m.algorithm)
		} else if m.algorithm == AlgorithmECDSA {
			algDesc = fmt.Sprintf("%s P-%d key", m.algorithm, m.bits)
		}
		return "\n" +
			pad + titleStyle.Render(AppTitle) + "\n\n" +
			pad + m.progress.View() + "\n\n" +
			pad + fmt.Sprintf("Generating %s...", algDesc) + "\n" +
			pad + m.message + "\n\n" +
			pad + helpStyle("Please wait...")

	case "progress_complete":
		algDesc := fmt.Sprintf("%s key", m.algorithm)
		if m.algorithm == AlgorithmRSA {
			algDesc = fmt.Sprintf("%d-bit %s key", m.bits, m.algorithm)
		} else if m.algorithm == AlgorithmECDSA {
			algDesc = fmt.Sprintf("%s P-%d key", m.algorithm, m.bits)
		}
		return "\n" +
			pad + titleStyle.Render(AppTitle) + "\n\n" +
			pad + m.progress.View() + "\n\n" +
			pad + fmt.Sprintf("Generating %s...", algDesc) + "\n" +
			pad + m.message + "\n\n" +
			pad + helpStyle("Please wait...")

	case "complete":
		view := "\n" +
			pad + titleStyle.Render(AppTitle) + "\n" +
			pad + fmt.Sprintf("Version %s", AppVersion) + "\n\n" +
			pad + successStyle.Render("✅ Key generation completed successfully!") + "\n\n" +
			pad + fmt.Sprintf("Private key saved to: %s (permissions 0600)", m.privatePath) + "\n" +
			pad + fmt.Sprintf("Public key saved to:  %s (permissions 0644)", m.publicPath) + "\n"
		if m.comment != "" {
			view += pad + fmt.Sprintf("Key comment: %s", m.comment) + "\n\n"
		}
		return view + "\n" +
			pad + helpStyle("Press any key to exit")

	case "error":
		return "\n" +
			pad + titleStyle.Render(AppTitle) + "\n\n" +
			pad + errorStyle.Render("❌ Error occurred:") + "\n" +
			pad + m.message + "\n\n" +
			pad + helpStyle("Press any key to exit")

	default:
		return "\n" + pad + "Initializing..."
	}
}

// Check if files exist and need overwrite confirmation
func checkExistingFiles(privatePath, publicPath string) (bool, error) {
	privateExists := false
	publicExists := false

	if _, err := os.Stat(privatePath); err == nil {
		privateExists = true
	}
	if _, err := os.Stat(publicPath); err == nil {
		publicExists = true
	}

	return privateExists || publicExists, nil
}

// Run in non-interactive mode (command line arguments provided)
func runNonInteractive() {
	// flags
	bits := flag.Int("b", 4096, "RSA key size in bits")
	out := flag.String("f", "id_rsa", "output filename for private key (public will be <f>.pub)")
	comment := flag.String("C", "", "key comment (e.g., user@host)")
	force := flag.Bool("force", false, "overwrite existing files")
	flag.Parse()

	privatePath := *out
	publicPath := privatePath + ".pub"

	// check existing files
	if !*force {
		if _, err := os.Stat(privatePath); err == nil {
			fmt.Fprintf(os.Stderr, "error: private key file %s already exists (use -force to overwrite)\n", privatePath)
			os.Exit(2)
		}
		if _, err := os.Stat(publicPath); err == nil {
			fmt.Fprintf(os.Stderr, "error: public key file %s already exists (use -force to overwrite)\n", publicPath)
			os.Exit(2)
		}
	}

	// generate (non-interactive mode currently only supports RSA)
	algorithm := AlgorithmRSA
	fmt.Printf("Generating %d-bit RSA key...\n", *bits)
	priv, err := generateRSAKey(*bits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating RSA key: %v\n", err)
		os.Exit(1)
	}

	// encode private
	privPEM, err := encodePrivateKeyToPEM(priv, algorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding private key: %v\n", err)
		os.Exit(1)
	}

	// encode public
	pubKey, err := publicKeySSHPublicKey(priv, algorithm, *comment)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating ssh public key: %v\n", err)
		os.Exit(1)
	}

	// write private with 0600
	if err := writeFileAtomic(privatePath, privPEM, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing private key: %v\n", err)
		os.Exit(1)
	}

	// write public with 0644
	if err := writeFileAtomic(publicPath, pubKey, 0o644); err != nil {
		// try to remove private if public write fails
		_ = os.Remove(privatePath)
		fmt.Fprintf(os.Stderr, "error writing public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Private key saved to %s (permissions 0600)\n", privatePath)
	fmt.Printf("Public key saved to %s (permissions 0644)\n", publicPath)
	if *comment != "" {
		fmt.Printf("Key comment: %s\n", *comment)
	}
}

// Run in interactive mode (no command line arguments)
func runInteractive() {
	// Initialize model
	m := model{
		progress:    progress.New(progress.WithDefaultGradient()),
		state:       "algorithm_selection",
		selectedIdx: 0,
		algorithm:   "",
		comment:     "",
		force:       false,
	}

	// Start the program
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error running interactive mode:", err)
		os.Exit(1)
	}
}

func main() {
	// Check if any command line arguments were provided
	if len(os.Args) > 1 {
		// Run in non-interactive mode
		runNonInteractive()
	} else {
		// Run in interactive mode
		runInteractive()
	}
}