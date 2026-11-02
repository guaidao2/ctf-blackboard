package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/guaidao2/ctf-blackboard/internal/server"
)

func main() {
	var (
		listen    = flag.String("listen", "0.0.0.0:8443", "监听地址，例如 0.0.0.0:8443")
		dataDir   = flag.String("data", "./data", "数据目录（state.json、证书、server-info.txt）")
		password  = flag.String("password", "", "共享密码（不推荐，进程列表可见；优先用 --password-file 或环境变量）")
		passFile  = flag.String("password-file", "", "从文件读取共享密码")
		name      = flag.String("name", "CTF Blackboard", "黑板名称")
		motd      = flag.String("motd", "把战果、容器位和 writeup 都放这里。", "公告")
		slots     = flag.Int("slots", 5, "首次启动的容器位上限（之后可在 GUI 里随时修改）")
		total     = flag.Int("total", 0, "首次启动的题目总数（之后可在 GUI 里随时修改）")
		publicURL = flag.String("public-url", "", "给队员的地址，例如 wss://10.0.0.5:8443/ws（默认自动推导）")
		certFile  = flag.String("cert", "", "TLS 证书路径（默认自动生成在 data 目录）")
		keyFile   = flag.String("key", "", "TLS 私钥路径（默认自动生成在 data 目录）")
		version   = flag.Bool("version", false, "打印版本")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "CTF Blackboard server %s\n\n", server.Version)
		fmt.Fprintf(flag.CommandLine.Output(), "用法: ctfbb-server [参数]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\n密码优先级: --password > --password-file > CTFBB_PASSWORD > 交互输入\n")
	}
	flag.Parse()

	if *version {
		fmt.Println(server.Version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	pass, err := resolvePassword(*password, *passFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取密码失败:", err)
		os.Exit(1)
	}
	if pass == "" {
		fmt.Fprintln(os.Stderr, "共享密码不能为空")
		os.Exit(1)
	}

	cfg := server.Config{
		Listen:          *listen,
		DataDir:         *dataDir,
		Password:        pass,
		ServerName:      *name,
		Motd:            *motd,
		SlotLimit:       *slots,
		TotalChallenges: *total,
		PublicURL:       *publicURL,
		CertFile:        *certFile,
		KeyFile:         *keyFile,
		Logger:          logger,
	}

	srv, err := server.New(cfg)
	if err != nil {
		logger.Error("启动失败", "err", err)
		os.Exit(1)
	}

	info, err := srv.Start()
	if err != nil {
		logger.Error("监听失败", "err", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("  CTF Blackboard v%s 已启动\n", server.Version)
	fmt.Printf("  地址   %s\n", info.URL)
	fmt.Printf("  指纹   %s\n", info.Pin)
	fmt.Printf("  监听   %s\n", info.Listen)
	fmt.Printf("  数据   %s\n", info.DataFile)
	fmt.Printf("  信息   %s\n", filepath.Join(filepath.Dir(info.DataFile), "server-info.txt"))
	fmt.Printf("  容器位 %d（可在客户端随时修改）\n", info.Settings.SlotLimit)
	fmt.Printf("  题目数 %d（可在客户端随时修改）\n", info.Settings.TotalChallenges)
	fmt.Println()
	fmt.Println("  把 server-info.txt、客户端和密码通过安全渠道发给队员。")
	fmt.Println("  Ctrl+C 停止服务（会保存状态）。")
	fmt.Println()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("正在关闭…")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Close(shutdownCtx); err != nil {
		logger.Error("关闭失败", "err", err)
		os.Exit(1)
	}
	logger.Info("已停止")
}

func resolvePassword(flagValue, file string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		p := strings.TrimSpace(string(raw))
		if p == "" {
			return "", fmt.Errorf("密码文件为空")
		}
		return p, nil
	}
	if env := os.Getenv("CTFBB_PASSWORD"); env != "" {
		return env, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("没有终端可交互输入，请用 --password-file 或 CTFBB_PASSWORD")
	}
	fmt.Fprint(os.Stderr, "共享密码: ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(string(raw))
	if p == "" {
		return "", fmt.Errorf("密码不能为空")
	}
	return p, nil
}
