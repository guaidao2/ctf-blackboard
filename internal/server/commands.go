package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/model"
	"github.com/guaidao2/ctf-blackboard/internal/protocol"
)

// dispatch serializes all state mutations under the hub lock. It returns the
// response envelope; the read loop fills in ReplyTo.
func (h *Hub) dispatch(c *Client, req protocol.Request) protocol.Envelope {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return protocol.NewErrorResponse("", "服务端正在关闭")
	}

	switch req.Cmd {
	case protocol.CmdStateGet:
		return protocol.NewResponse("", h.snapshotLocked(c.nick))
	case protocol.CmdChatSend:
		return h.cmdChatSend(c, req)
	case protocol.CmdSolverAdd:
		return h.cmdSolverAdd(c, req)
	case protocol.CmdSolverGet:
		return h.cmdSolverGet(req)
	case protocol.CmdSolverUpdate:
		return h.cmdSolverUpdate(c, req)
	case protocol.CmdSolverDelete:
		return h.cmdSolverDelete(c, req)
	case protocol.CmdSlotOpen:
		return h.cmdSlotOpen(c, req)
	case protocol.CmdSlotUpdate:
		return h.cmdSlotUpdate(c, req)
	case protocol.CmdSlotRelease:
		return h.cmdSlotRelease(c, req)
	case protocol.CmdSettingsUpdate:
		return h.cmdSettingsUpdate(c, req)
	case protocol.CmdKick:
		return h.cmdKick(c, req)
	default:
		return protocol.NewErrorResponse("", "未知命令："+req.Cmd)
	}
}

func decodeArgs[T any](req protocol.Request) (T, error) {
	var v T
	if len(req.Args) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(req.Args, &v); err != nil {
		return v, fmt.Errorf("参数格式错误")
	}
	return v, nil
}

func (h *Hub) cmdChatSend(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.ChatSendArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	text, err := validateChat(args.Text)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	if !c.allowChat(time.Now()) {
		return protocol.NewErrorResponse("", "发言太快，缓一下")
	}
	msg := h.addChatLocked(c.nick, text, model.MessageChat)
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	return protocol.NewResponse("", protocol.MessageEvent{Message: msg})
}

func (h *Hub) cmdSolverAdd(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.SolverAddArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	challenge, err := validateChallenge(args.Challenge)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	nick := strings.TrimSpace(args.Nick)
	if nick == "" {
		nick = c.nick
	}
	nick, err = normalizeNick(nick)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	if existing := h.state.FindSolverByChallenge(challenge); existing != nil {
		return protocol.NewErrorResponse("", fmt.Sprintf("这题已有战果：%s（%s 提交），直接编辑即可", existing.Challenge, existing.Nick))
	}
	writeup, err := validateWriteup(args.Writeup, h.cfg.MaxWriteupBytes)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}

	now := time.Now().UTC()
	sv := &model.Solver{
		ID:         newID(),
		Challenge:  challenge,
		Nick:       nick,
		Writeup:    writeup,
		HasWriteup: strings.TrimSpace(writeup) != "",
		CreatedBy:  c.nick,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	h.state.Solvers = append(h.state.Solvers, sv)
	h.addActivityLocked(c.nick, "solver.add", fmt.Sprintf("记录战果：%s（%s）", challenge, nick))
	h.addChatLocked(nick, fmt.Sprintf("✅ %s 交了 %s 的 flag", nick, challenge), model.MessageSolve)

	board := h.boardLocked()
	result := protocol.SolverResult{Solver: *sv, Board: board}
	eventSolver := *sv
	eventSolver.Writeup = ""
	h.broadcastLocked(protocol.EventSolverUpsert, protocol.SolverResult{Solver: eventSolver, Board: board})
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	return protocol.NewResponse("", result)
}

func (h *Hub) cmdSolverGet(req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.IDArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	sv := h.state.FindSolver(args.ID)
	if sv == nil {
		return protocol.NewErrorResponse("", "战果不存在")
	}
	cp := *sv
	cp.HasWriteup = strings.TrimSpace(cp.Writeup) != ""
	return protocol.NewResponse("", protocol.SolverResult{Solver: cp, Board: h.boardLocked()})
}

func (h *Hub) cmdSolverUpdate(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.SolverUpdateArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	sv := h.state.FindSolver(args.ID)
	if sv == nil {
		return protocol.NewErrorResponse("", "战果不存在")
	}
	challenge, err := validateChallenge(args.Challenge)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	nick, err := normalizeNick(args.Nick)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	writeup, err := validateWriteup(args.Writeup, h.cfg.MaxWriteupBytes)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	if existing := h.state.FindSolverByChallenge(challenge); existing != nil && existing.ID != sv.ID {
		return protocol.NewErrorResponse("", fmt.Sprintf("题目 %s 已有另一条战果（%s）", existing.Challenge, existing.Nick))
	}

	sv.Challenge = challenge
	sv.Nick = nick
	sv.Writeup = writeup
	sv.HasWriteup = strings.TrimSpace(writeup) != ""
	sv.UpdatedAt = time.Now().UTC()

	h.addActivityLocked(c.nick, "solver.update", fmt.Sprintf("更新战果：%s（%s）", challenge, nick))
	board := h.boardLocked()
	result := protocol.SolverResult{Solver: *sv, Board: board}
	eventSolver := *sv
	eventSolver.Writeup = ""
	h.broadcastLocked(protocol.EventSolverUpsert, protocol.SolverResult{Solver: eventSolver, Board: board})
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	return protocol.NewResponse("", result)
}

func (h *Hub) cmdSolverDelete(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.IDArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	idx := -1
	for i, sv := range h.state.Solvers {
		if sv.ID == args.ID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return protocol.NewErrorResponse("", "战果不存在")
	}
	sv := h.state.Solvers[idx]
	copy(h.state.Solvers[idx:], h.state.Solvers[idx+1:])
	h.state.Solvers[len(h.state.Solvers)-1] = nil
	h.state.Solvers = h.state.Solvers[:len(h.state.Solvers)-1]

	h.addActivityLocked(c.nick, "solver.delete", fmt.Sprintf("删除战果：%s（%s）", sv.Challenge, sv.Nick))
	h.addChatLocked("系统", fmt.Sprintf("🗑 %s 删除了 %s 的战果", c.nick, sv.Challenge), model.MessageSystem)
	board := h.boardLocked()
	result := protocol.SolverDeleted{ID: sv.ID, Board: board}
	h.broadcastLocked(protocol.EventSolverDelete, result)
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	return protocol.NewResponse("", result)
}

func (h *Hub) cmdSlotOpen(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.SlotOpenArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	challenge, err := validateChallenge(args.Challenge)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	url, err := validateURL(args.URL)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	notes, err := validateNotes(args.Notes)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	if active := h.state.ActiveSlots(); active >= h.state.Settings.SlotLimit {
		return protocol.NewErrorResponse("", h.slotFullMessageLocked())
	}

	now := time.Now().UTC()
	sl := &model.Slot{
		ID:        newID(),
		Challenge: challenge,
		Owner:     c.nick,
		URL:       url,
		Notes:     notes,
		Status:    model.SlotActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	h.state.Slots = append(h.state.Slots, sl)
	h.addActivityLocked(c.nick, "slot.open", fmt.Sprintf("占用容器位：%s", challenge))
	h.addChatLocked("系统", fmt.Sprintf("📦 %s 占了 %s 的容器位", c.nick, challenge), model.MessageSystem)

	board := h.boardLocked()
	result := protocol.SlotResult{Slot: *sl, Board: board}
	h.broadcastLocked(protocol.EventSlotUpsert, result)
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	return protocol.NewResponse("", result)
}

func (h *Hub) cmdSlotUpdate(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.SlotUpdateArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	sl := h.state.FindSlot(args.ID)
	if sl == nil {
		return protocol.NewErrorResponse("", "容器位不存在")
	}
	if !sl.Active() {
		return protocol.NewErrorResponse("", "这个容器位已经释放，不能再编辑")
	}
	challenge, err := validateChallenge(args.Challenge)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	url, err := validateURL(args.URL)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	notes, err := validateNotes(args.Notes)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}

	sl.Challenge = challenge
	sl.URL = url
	sl.Notes = notes
	sl.UpdatedAt = time.Now().UTC()

	h.addActivityLocked(c.nick, "slot.update", fmt.Sprintf("编辑容器位：%s", challenge))
	board := h.boardLocked()
	result := protocol.SlotResult{Slot: *sl, Board: board}
	h.broadcastLocked(protocol.EventSlotUpsert, result)
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	return protocol.NewResponse("", result)
}

func (h *Hub) cmdSlotRelease(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.IDArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	sl := h.state.FindSlot(args.ID)
	if sl == nil {
		return protocol.NewErrorResponse("", "容器位不存在")
	}
	if !sl.Active() {
		return protocol.NewErrorResponse("", "这个容器位已经释放")
	}
	now := time.Now().UTC()
	sl.Status = model.SlotReleased
	sl.ReleasedAt = now
	sl.UpdatedAt = now

	h.addActivityLocked(c.nick, "slot.release", fmt.Sprintf("释放容器位：%s", sl.Challenge))
	h.addChatLocked("系统", fmt.Sprintf("📦 %s 释放了 %s 的容器位", c.nick, sl.Challenge), model.MessageSystem)

	board := h.boardLocked()
	result := protocol.SlotResult{Slot: *sl, Board: board}
	h.broadcastLocked(protocol.EventSlotUpsert, result)
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	return protocol.NewResponse("", result)
}

func (h *Hub) cmdSettingsUpdate(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.SettingsUpdateArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}

	// Validate every supplied field before mutating anything, so a bad
	// slot_limit cannot leave total_challenges applied but unpersisted.
	next := h.state.Settings
	if args.TotalChallenges != nil {
		v := *args.TotalChallenges
		if v < 0 || v > 10000 {
			return protocol.NewErrorResponse("", "题目总数必须在 0 到 10000 之间")
		}
		if v < len(h.state.Solvers) {
			return protocol.NewErrorResponse("", fmt.Sprintf("题目总数不能小于已解数量（当前 %d 条战果）", len(h.state.Solvers)))
		}
		next.TotalChallenges = v
	}
	if args.SlotLimit != nil {
		v := *args.SlotLimit
		if v < 0 || v > 1000 {
			return protocol.NewErrorResponse("", "容器位上限必须在 0 到 1000 之间")
		}
		next.SlotLimit = v
	}
	if args.Motd != nil {
		motd, err := validateMotd(*args.Motd)
		if err != nil {
			return protocol.NewErrorResponse("", err.Error())
		}
		next.Motd = motd
	}
	h.state.Settings = next

	h.addActivityLocked(c.nick, "settings.update",
		fmt.Sprintf("更新设置：题目总数 %d，容器位上限 %d", h.state.Settings.TotalChallenges, h.state.Settings.SlotLimit))
	board := h.boardLocked()
	result := protocol.SettingsResult{Settings: h.state.Settings, Board: board}
	h.broadcastLocked(protocol.EventSettings, result)
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	return protocol.NewResponse("", result)
}

func (h *Hub) cmdKick(c *Client, req protocol.Request) protocol.Envelope {
	args, err := decodeArgs[protocol.KickArgs](req)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	nick, err := normalizeNick(args.Nick)
	if err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}
	if strings.EqualFold(nick, c.nick) {
		return protocol.NewErrorResponse("", "不能踢自己")
	}
	target := h.findClientLocked(nick)
	if target == nil {
		return protocol.NewErrorResponse("", "该操作员不在线")
	}

	target.kicked.Store(true)
	until := time.Now().Add(h.cfg.KickCooldown)
	h.kickCooldown[lowerNick(nick)] = until
	h.sendEventLocked(target, protocol.EventKicked, protocol.KickedEvent{
		By:     c.nick,
		Reason: fmt.Sprintf("被 %s 踢出，%d 秒内不能重连", c.nick, int(h.cfg.KickCooldown.Seconds())),
	})

	delete(h.clients, target)
	if h.byNick[lowerNick(nick)] == target {
		delete(h.byNick, lowerNick(nick))
	}
	h.addActivityLocked(c.nick, "kick", fmt.Sprintf("踢出操作员：%s", target.nick))
	h.addChatLocked("系统", fmt.Sprintf("👢 %s 把 %s 踢出了黑板", c.nick, target.nick), model.MessageSystem)
	board := h.boardLocked()
	h.broadcastLocked(protocol.EventBoard, protocol.BoardEvent{Board: board})
	if err := h.saveLocked(); err != nil {
		return protocol.NewErrorResponse("", err.Error())
	}

	// Give the writer a moment to flush the kicked event before closing.
	time.AfterFunc(150*time.Millisecond, target.close)
	return protocol.NewResponse("", nil)
}

func (h *Hub) slotFullMessageLocked() string {
	active := make([]string, 0)
	for _, sl := range h.state.Slots {
		if sl.Active() {
			active = append(active, fmt.Sprintf("%s（%s）", sl.Challenge, sl.Owner))
		}
	}
	if len(active) == 0 {
		return fmt.Sprintf("容器位上限是 %d，先把上限调大再开", h.state.Settings.SlotLimit)
	}
	return fmt.Sprintf("容器位已满（%d/%d）：%s。先释放一个再开。",
		h.state.ActiveSlots(), h.state.Settings.SlotLimit, strings.Join(active, "；"))
}
