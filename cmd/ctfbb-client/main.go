package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/client"
)

func main() {
	var (
		serverAddr = flag.String("server", "", "预填服务器地址，例如 wss://10.0.0.5:8443/ws")
		pin        = flag.String("pin", "", "预填证书指纹")
		nick       = flag.String("nick", "", "预填昵称")
		infoFile   = flag.String("server-info", "", "从服务端生成的 server-info.txt 预填地址和指纹")
		knownHosts = flag.String("known-hosts", "", "known_hosts 文件路径（默认用户配置目录）")
		listen     = flag.String("listen", "127.0.0.1:0", "本地 GUI 监听地址（默认随机回环端口）")
		allowUI    = flag.Bool("allow-remote-ui", false, "允许本地 GUI 绑定非回环地址（不推荐）")
		noOpen     = flag.Bool("no-open", false, "不自动打开浏览器，只打印地址")
		version    = flag.Bool("version", false, "打印版本")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "CTF Blackboard client %s\n\n", client.Version)
		fmt.Fprintf(flag.CommandLine.Output(), "用法: ctfbb-client [参数]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\n客户端会在本机 127.0.0.1 启动 GUI，密码只在 GUI 里输入。\n")
	}
	flag.Parse()

	if *version {
		fmt.Println(client.Version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	prefill := client.Prefill{URL: *serverAddr, Pin: *pin, Nick: *nick}
	infoPath := *infoFile
	discovered := false
	if infoPath == "" {
		if p, ok := discoverServerInfo(); ok {
			infoPath = p
			discovered = true
		}
	}
	if infoPath != "" {
		info, err := readServerInfo(infoPath)
		if err != nil {
			if discovered {
				logger.Warn("发现 server-info.txt 但读取失败，改为手动登录", "file", infoPath, "err", err)
			} else {
				fmt.Fprintln(os.Stderr, "读取 server-info.txt 失败:", err)
				os.Exit(1)
			}
		} else {
			if prefill.URL == "" {
				prefill.URL = info.URL
			}
			if prefill.Pin == "" {
				prefill.Pin = info.Pin
			}
			logger.Info("已读取服务器信息", "file", infoPath)
		}
	}

	bridge, err := client.NewBridge(client.Options{
		Prefill:            prefill,
		Listen:             *listen,
		Logger:             logger,
		KnownHostsPath:     *knownHosts,
		AllowNonLoopbackUI: *allowUI,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
	uiURL, err := bridge.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("  CTF Blackboard client v%s\n", client.Version)
	fmt.Printf("  GUI   %s\n", uiURL)
	if *noOpen {
		fmt.Println("  已禁用自动打开浏览器，请手动访问上面的地址。")
	} else if err := openBrowser(uiURL); err != nil {
		fmt.Printf("  自动打开浏览器失败：%v\n", err)
		fmt.Println("  请手动访问上面的地址。")
	}
	fmt.Println("  Ctrl+C 退出客户端。")
	fmt.Println()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case <-bridge.Quit():
	}

	logger.Info("正在关闭客户端…")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = bridge.Close(shutdownCtx)
	logger.Info("已退出")
}

type serverInfo struct {
	URL  string
	Pin  string
	Name string
}

// discoverServerInfo looks next to the working directory and the executable,
// so a teammate can drop server-info.txt beside the client and just run it.
func discoverServerInfo() (string, bool) {
	candidates := []string{
		"server-info.txt",
		filepath.Join("data", "server-info.txt"),
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "server-info.txt"),
			filepath.Join(dir, "data", "server-info.txt"),
		)
	}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err == nil {
			if seen[abs] {
				continue
			}
			seen[abs] = true
		}
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

// readServerInfo parses the key=value file written by ctfbb-server.
func readServerInfo(path string) (serverInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return serverInfo{}, err
	}
	defer f.Close()

	var info serverInfo
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "url":
			info.URL = strings.TrimSpace(value)
		case "pin":
			info.Pin = strings.TrimSpace(value)
		case "name":
			info.Name = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return serverInfo{}, err
	}
	if info.URL == "" || info.Pin == "" {
		return serverInfo{}, fmt.Errorf("%s 缺少 url= 或 pin=", filepath.Base(path))
	}
	return info, nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
