package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GagarinRu/gophkeeper/internal/client"
	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/GagarinRu/gophkeeper/internal/logger"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"go.uber.org/zap"
)

type cliConfig struct {
	ServerURL     string
	TokenFile     string
	CacheFile     string
	LogLevel      string
	CryptoKeyPath string
}

func runCLI(cfg cliConfig, args []string) int {
	if len(args) == 0 {
		fmt.Println("usage: gophkeeper-client <command> [flags]")
		fmt.Println("commands: version, register, login, logout, add, list, get, update, delete, sync")
		return 1
	}

	cmd := args[0]
	switch cmd {
	case "version":
		printBuildInfo()
		return 0
	case "register", "login", "logout", "add", "list", "get", "update", "delete", "sync":
		if err := logger.Initialize(cfg.LogLevel); err != nil {
			panic("Failed to initialize logger: " + err.Error())
		}
		defer func() { _ = logger.Log.Sync() }()
		return runCommand(cfg, cmd, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		return 1
	}
}

func runCommand(cfg cliConfig, cmd string, args []string) int {
	api := client.NewAPI(cfg.ServerURL)
	token, err := loadToken(cfg.TokenFile)
	if err != nil {
		logger.Log.Error("Failed to load token", zap.Error(err))
		return 1
	}
	api.SetToken(token)
	if cfg.CryptoKeyPath != "" {
		pub, err := crypto.LoadPublicKey(cfg.CryptoKeyPath)
		if err != nil {
			logger.Log.Error("Failed to load public key", zap.String("path", cfg.CryptoKeyPath), zap.Error(err))
			return 1
		}
		api.SetPublicKey(pub)
	}

	switch cmd {
	case "register":
		return cmdRegister(api, cfg.TokenFile, args)
	case "login":
		return cmdLogin(api, cfg.TokenFile, args)
	case "logout":
		return cmdLogout(api, cfg.TokenFile, cfg.CacheFile)
	case "add":
		return cmdAdd(api, args)
	case "list":
		return cmdList(api, args)
	case "get":
		return cmdGet(api, args)
	case "update":
		return cmdUpdate(api, args)
	case "delete":
		return cmdDelete(api, args)
	case "sync":
		return cmdSync(api, cfg.CacheFile)
	default:
		return 1
	}
}

func cmdRegister(api *client.API, tokenFile string, args []string) int {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	email := fs.String("email", "", "User email")
	password := fs.String("password", "", "User password")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *email == "" || *password == "" {
		logger.Log.Error("Email and password are required")
		return 1
	}
	token, err := api.Register(*email, *password)
	if err != nil {
		logger.Log.Error("Registration failed", zap.Error(err))
		return 1
	}
	if err := saveToken(tokenFile, token); err != nil {
		logger.Log.Error("Failed to save token", zap.Error(err))
		return 1
	}
	logger.Log.Info("Registration successful", zap.String("email", *email))
	return 0
}

func cmdLogin(api *client.API, tokenFile string, args []string) int {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	email := fs.String("email", "", "User email")
	password := fs.String("password", "", "User password")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *email == "" || *password == "" {
		logger.Log.Error("Email and password are required")
		return 1
	}
	token, err := api.Login(*email, *password)
	if err != nil {
		logger.Log.Error("Login failed", zap.Error(err))
		return 1
	}
	if err := saveToken(tokenFile, token); err != nil {
		logger.Log.Error("Failed to save token", zap.Error(err))
		return 1
	}
	logger.Log.Info("Login successful", zap.String("email", *email))
	return 0
}

func cmdLogout(api *client.API, tokenFile, cacheFile string) int {
	if err := api.Logout(); err != nil {
		logger.Log.Warn("Server logout failed", zap.Error(err))
	}
	if err := os.Remove(tokenFile); err != nil && !os.IsNotExist(err) {
		logger.Log.Error("Failed to remove token", zap.Error(err))
		return 1
	}
	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		logger.Log.Error("Failed to remove cache", zap.Error(err))
		return 1
	}
	logger.Log.Info("Logged out")
	return 0
}

func cmdAdd(api *client.API, args []string) int {
	if len(args) == 0 {
		logger.Log.Error("add requires a type: login, text, binary, card")
		return 1
	}
	switch args[0] {
	case "login":
		return cmdAddLogin(api, args[1:])
	case "text":
		return cmdAddText(api, args[1:])
	case "binary":
		return cmdAddBinary(api, args[1:])
	case "card":
		return cmdAddCard(api, args[1:])
	default:
		logger.Log.Error("Unknown add type", zap.String("type", args[0]))
		return 1
	}
}

func cmdAddLogin(api *client.API, args []string) int {
	fs := flag.NewFlagSet("add login", flag.ExitOnError)
	name := fs.String("name", "", "Secret name")
	login := fs.String("login", "", "Login")
	password := fs.String("password", "", "Password")
	url := fs.String("url", "", "URL")
	metadata := fs.String("metadata", "", "Metadata")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	payload, err := json.Marshal(models.LoginPasswordPayload{
		Login:    *login,
		Password: *password,
		URL:      *url,
	})
	if err != nil {
		return 1
	}
	secret, err := api.CreateSecret(models.SecretTypeLoginPassword, *name, *metadata, payload)
	if err != nil {
		logger.Log.Error("Failed to create secret", zap.Error(err))
		return 1
	}
	fmt.Printf("created secret %s\n", secret.ID)
	return 0
}

func cmdAddText(api *client.API, args []string) int {
	fs := flag.NewFlagSet("add text", flag.ExitOnError)
	name := fs.String("name", "", "Secret name")
	content := fs.String("content", "", "Text content")
	metadata := fs.String("metadata", "", "Metadata")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	payload, err := json.Marshal(models.TextPayload{Content: *content})
	if err != nil {
		return 1
	}
	secret, err := api.CreateSecret(models.SecretTypeText, *name, *metadata, payload)
	if err != nil {
		logger.Log.Error("Failed to create secret", zap.Error(err))
		return 1
	}
	fmt.Printf("created secret %s\n", secret.ID)
	return 0
}

func cmdAddBinary(api *client.API, args []string) int {
	fs := flag.NewFlagSet("add binary", flag.ExitOnError)
	name := fs.String("name", "", "Secret name")
	filePath := fs.String("file", "", "Path to binary file")
	metadata := fs.String("metadata", "", "Metadata")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	data, err := os.ReadFile(*filePath)
	if err != nil {
		logger.Log.Error("Failed to read file", zap.Error(err))
		return 1
	}
	payload, err := json.Marshal(models.BinaryPayload{
		Filename: filepath.Base(*filePath),
		Data:     data,
	})
	if err != nil {
		return 1
	}
	secret, err := api.CreateSecret(models.SecretTypeBinary, *name, *metadata, payload)
	if err != nil {
		logger.Log.Error("Failed to create secret", zap.Error(err))
		return 1
	}
	fmt.Printf("created secret %s\n", secret.ID)
	return 0
}

func cmdAddCard(api *client.API, args []string) int {
	fs := flag.NewFlagSet("add card", flag.ExitOnError)
	name := fs.String("name", "", "Secret name")
	number := fs.String("number", "", "Card number")
	holder := fs.String("holder", "", "Card holder")
	expiry := fs.String("expiry", "", "Expiry date")
	cvv := fs.String("cvv", "", "CVV")
	metadata := fs.String("metadata", "", "Metadata")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	payload, err := json.Marshal(models.CardPayload{
		Number: *number,
		Holder: *holder,
		Expiry: *expiry,
		CVV:    *cvv,
	})
	if err != nil {
		return 1
	}
	secret, err := api.CreateSecret(models.SecretTypeCard, *name, *metadata, payload)
	if err != nil {
		logger.Log.Error("Failed to create secret", zap.Error(err))
		return 1
	}
	fmt.Printf("created secret %s\n", secret.ID)
	return 0
}

func cmdList(api *client.API, args []string) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	secretType := fs.String("type", "", "Filter by secret type")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	secrets, err := api.ListSecrets(models.SecretType(*secretType))
	if err != nil {
		logger.Log.Error("Failed to list secrets", zap.Error(err))
		return 1
	}
	for _, s := range secrets {
		fmt.Printf("%s  %s  %s  %s\n", s.ID, s.Type, s.Name, s.UpdatedAt.Format("2006-01-02 15:04:05"))
	}
	return 0
}

func cmdGet(api *client.API, args []string) int {
	if len(args) == 0 {
		logger.Log.Error("get requires secret id")
		return 1
	}
	secret, err := api.GetSecret(args[0])
	if err != nil {
		logger.Log.Error("Failed to get secret", zap.Error(err))
		return 1
	}
	data, err := json.MarshalIndent(secret, "", "  ")
	if err != nil {
		return 1
	}
	fmt.Println(string(data))
	return 0
}

func cmdUpdate(api *client.API, args []string) int {
	if len(args) == 0 {
		logger.Log.Error("update requires secret id")
		return 1
	}
	id := args[0]
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	name := fs.String("name", "", "Secret name")
	metadata := fs.String("metadata", "", "Metadata")
	content := fs.String("content", "", "Text content (for text secrets)")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	existing, err := api.GetSecret(id)
	if err != nil {
		logger.Log.Error("Failed to get secret", zap.Error(err))
		return 1
	}
	updateName := existing.Name
	if *name != "" {
		updateName = *name
	}
	updateMeta := existing.Metadata
	if *metadata != "" {
		updateMeta = *metadata
	}
	payload := existing.Payload
	if *content != "" && existing.Type == models.SecretTypeText {
		payload, err = json.Marshal(models.TextPayload{Content: *content})
		if err != nil {
			return 1
		}
	}
	secret, err := api.UpdateSecret(id, existing.Type, updateName, updateMeta, payload)
	if err != nil {
		logger.Log.Error("Failed to update secret", zap.Error(err))
		return 1
	}
	fmt.Printf("updated secret %s\n", secret.ID)
	return 0
}

func cmdDelete(api *client.API, args []string) int {
	if len(args) == 0 {
		logger.Log.Error("delete requires secret id")
		return 1
	}
	if err := api.DeleteSecret(args[0]); err != nil {
		logger.Log.Error("Failed to delete secret", zap.Error(err))
		return 1
	}
	logger.Log.Info("Secret deleted", zap.String("id", args[0]))
	return 0
}

func cmdSync(api *client.API, cacheFile string) int {
	cache, err := client.LoadCache(cacheFile)
	if err != nil {
		logger.Log.Error("Failed to load cache", zap.Error(err))
		return 1
	}
	secrets, err := api.Sync(cache.LastSync)
	if err != nil {
		logger.Log.Error("Sync failed", zap.Error(err))
		return 1
	}
	client.MergeSecrets(cache, secrets)
	if err := client.SaveCache(cacheFile, cache); err != nil {
		logger.Log.Error("Failed to save cache", zap.Error(err))
		return 1
	}
	logger.Log.Info("Sync completed", zap.Int("changes", len(secrets)), zap.Int("cached", len(cache.Secrets)))
	return 0
}

func loadToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func saveToken(path string, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(token), 0o600)
}
