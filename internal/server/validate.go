package server

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

func normalizeNick(raw string) (string, error) {
	nick := strings.TrimSpace(raw)
	if nick == "" {
		return "", fmt.Errorf("昵称不能为空")
	}
	if utf8.RuneCountInString(nick) > 24 {
		return "", fmt.Errorf("昵称最多 24 个字符")
	}
	for _, r := range nick {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", fmt.Errorf("昵称不能包含空格或控制字符")
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			continue
		}
		return "", fmt.Errorf("昵称只能包含中英文、数字、下划线、点和短横线")
	}
	switch strings.ToLower(nick) {
	case "system", "server", "系统", "服务端":
		return "", fmt.Errorf("这个昵称是保留的，请换一个")
	}
	return nick, nil
}

func validateChallenge(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("题目名称不能为空")
	}
	if utf8.RuneCountInString(s) > 80 {
		return "", fmt.Errorf("题目名称最多 80 个字符")
	}
	if hasControl(s) {
		return "", fmt.Errorf("题目名称不能包含控制字符")
	}
	return s, nil
}

func validateURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if utf8.RuneCountInString(s) > 500 {
		return "", fmt.Errorf("URL 最多 500 个字符")
	}
	if hasControl(s) {
		return "", fmt.Errorf("URL 不能包含控制字符")
	}
	return s, nil
}

func validateNotes(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if utf8.RuneCountInString(s) > 2000 {
		return "", fmt.Errorf("备注最多 2000 个字符")
	}
	if strings.ContainsRune(s, '\x00') {
		return "", fmt.Errorf("备注包含非法字符")
	}
	return s, nil
}

func validateChat(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("消息不能为空")
	}
	if utf8.RuneCountInString(s) > 2000 {
		return "", fmt.Errorf("消息最多 2000 个字符")
	}
	if hasControl(s) {
		return "", fmt.Errorf("消息不能包含控制字符")
	}
	return s, nil
}

func validateWriteup(raw string, maxBytes int) (string, error) {
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("writeup 不是有效的 UTF-8")
	}
	if len(raw) > maxBytes {
		return "", fmt.Errorf("writeup 超过 %d KB 上限", maxBytes/1024)
	}
	if strings.ContainsRune(raw, '\x00') {
		return "", fmt.Errorf("writeup 包含非法字符")
	}
	return raw, nil
}

func validateMotd(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if utf8.RuneCountInString(s) > 1000 {
		return "", fmt.Errorf("公告最多 1000 个字符")
	}
	if strings.ContainsRune(s, '\x00') {
		return "", fmt.Errorf("公告包含非法字符")
	}
	return s, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
