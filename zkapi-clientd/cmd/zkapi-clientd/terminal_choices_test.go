package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func TestTerminalChoicesPlainOutputRetainsTextInput(t *testing.T) {
	var output bytes.Buffer
	ui := &terminalSetupPrompter{out: &output, input: bufio.NewReader(strings.NewReader("sepolia\n"))}
	answer, err := ui.Select(context.Background(), "Choose network", "mainnet", []setupChoice{
		{value: "mainnet", label: "Mainnet (real ETH)"},
		{value: "sepolia", label: "Sepolia (test ETH)"},
	})
	if err != nil || answer != "sepolia" || output.String() != "Choose network [mainnet]: " {
		t.Fatalf("plain output answer=%q, err=%v, output=%q", answer, err, output.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ui.Select(ctx, "Choose", "", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled selection returned %v", err)
	}
}

type choiceTestUI struct {
	startTestUI
	selected string
	choices  []setupChoice
	err      error
}

func (u *choiceTestUI) Select(_ context.Context, _, _ string, choices []setupChoice) (string, error) {
	u.choices = append([]setupChoice(nil), choices...)
	return u.selected, u.err
}

func TestConfigureUsesKeyboardChoices(t *testing.T) {
	dir, _ := startTestConfig(t)
	ui := &choiceTestUI{selected: "withdraw"}
	called := false
	err := configure(context.Background(), dir, []string{"--menu"}, ui, io.Discard, func(_ context.Context, _ string, _ config.Config, operation string, _ setupPrompter, _ io.Writer) error {
		called = operation == "withdraw"
		return nil
	})
	if err != nil || !called || len(ui.choices) != 8 || ui.choices[2].value != "password" || ui.choices[5].value != "repair" || ui.choices[7].value != "quit" {
		t.Fatalf("menu did not use named choices: called=%v err=%v choices=%v", called, err, ui.choices)
	}
	ui.selected = "mainnet"
	if choice, err := configureChoice(context.Background(), ui, "Network", "sepolia", "mainnet", "sepolia"); err != nil || choice != "mainnet" || len(ui.choices) != 2 {
		t.Fatalf("network choices: value=%q err=%v choices=%v", choice, err, ui.choices)
	}
}

func TestConfigureCanceledChoicePreservesSettings(t *testing.T) {
	dir, before := startTestConfig(t)
	ui := &choiceTestUI{err: errSetupSelectionCanceled}
	if err := runConfigure(context.Background(), dir, []string{"--edit"}, ui, io.Discard); err != nil {
		t.Fatal(err)
	}
	after, err := config.Load(dir)
	if err != nil || after != before || !strings.Contains(ui.output.String(), "Configuration canceled") {
		t.Fatalf("cancel changed settings: err=%v output=%q", err, ui.output.String())
	}
}

func TestChoiceRenderingFitsNarrowTerminal(t *testing.T) {
	var output bytes.Buffer
	choices := []setupChoice{{value: "one", label: "First choice"}, {value: "two", label: "Second choice"}, {value: "three", label: "Third choice"}}
	renderSetupChoices(&output, choices, 2, 2, 9)
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "> Third") || strings.Contains(output.String(), "First") {
		t.Fatalf("visible selection incorrect: %q", output.String())
	}
	for _, line := range lines {
		if len([]rune(strings.TrimPrefix(line, "\r\x1b[2K"))) > 8 {
			t.Fatalf("menu line wraps terminal: %q", line)
		}
	}
}

func TestTerminalChoicesPTYHelper(t *testing.T) {
	if os.Getenv("OA_TEST_CHOICES_PTY") != "1" {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	action := os.Getenv("OA_TEST_CHOICES_ACTION")
	if action == "timeout" {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, 450*time.Millisecond)
		defer stop()
	}
	ui := &terminalSetupPrompter{out: os.Stdout}
	defer ui.Close()
	choices := []setupChoice{{value: "one", label: "First choice"}, {value: "two", label: "Second choice"}, {value: "quit", label: "Quit"}}
	if action == "cancel" {
		choices = choices[:2]
	}
	answer, err := ui.Select(ctx, "PTY choose", "one", choices)
	switch action {
	case "enter", "resize-exit":
		if answer != "one" || err != nil {
			t.Fatalf("default answer=%q err=%v", answer, err)
		}
	case "down", "j", "resize":
		if answer != "two" || err != nil {
			t.Fatalf("next answer=%q err=%v", answer, err)
		}
	case "up", "escape", "q":
		if answer != "quit" || err != nil {
			t.Fatalf("quit answer=%q err=%v", answer, err)
		}
	case "cancel":
		if answer != "" || !errors.Is(err, errSetupSelectionCanceled) {
			t.Fatalf("cancel answer=%q err=%v", answer, err)
		}
	case "interrupt":
		if answer != "" || !errors.Is(err, context.Canceled) {
			t.Fatalf("interrupt answer=%q err=%v", answer, err)
		}
	case "timeout":
		if answer != "" || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout answer=%q err=%v", answer, err)
		}
	case "eof":
		if answer != "" || err == nil || ctx.Err() != nil {
			t.Fatalf("EOF answer=%q err=%v", answer, err)
		}
	default:
		t.Fatalf("unknown PTY action: %s", action)
	}
	fmt.Println("PTY_EXPECTED_CHOICE_RESULT")
}

func TestTerminalChoicesPTYNavigationAndRestoration(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python 3 is needed for the real PTY regression")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const harness = `
import errno, fcntl, os, pty, select, signal, struct, sys, termios, time

read_fd, write_fd = os.pipe()
os.write(write_fd, b"quit\n")
os.close(write_fd)
pid, terminal = pty.fork()
if pid == 0:
    os.dup2(read_fd, 0)
    os.close(read_fd)
    env = dict(os.environ, TERM="xterm-256color", OA_TEST_CHOICES_PTY="1", OA_TEST_CHOICES_ACTION=sys.argv[2])
    os.execve(sys.argv[1], [sys.argv[1], "-test.run=^TestTerminalChoicesPTYHelper$"], env)
os.close(read_fd)
original = termios.tcgetattr(terminal)
output = b""
reaped = False

def read_output():
    global output
    if select.select([terminal], [], [], 0.025)[0]:
        try:
            output += os.read(terminal, 4096)
        except OSError as error:
            if error.errno != errno.EIO:
                raise

try:
    deadline = time.monotonic() + 5
    while b"> First choice" not in output:
        read_output()
        exited, status = os.waitpid(pid, os.WNOHANG)
        if exited:
            reaped = True
            raise RuntimeError("menu exited early: " + repr(output))
        if time.monotonic() >= deadline:
            raise RuntimeError("menu did not appear: " + repr(output))
    during = termios.tcgetattr(terminal)
    if during[3] & (termios.ICANON | termios.ECHO) or not during[3] & termios.ISIG:
        raise RuntimeError("keyboard mode did not preserve signal handling")
    deadline = time.monotonic() + 0.1
    while time.monotonic() < deadline:
        read_output()
        if b"PTY_EXPECTED_CHOICE_RESULT" in output:
            raise RuntimeError("menu consumed piped stdin: " + repr(output))
    if sys.argv[2] in ("resize", "resize-exit"):
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 6, 24, 0, 0))
    if sys.argv[2] == "resize":
        os.write(terminal, b"\x1b[B")
        deadline = time.monotonic() + 2
        while output.count(b"PTY choose") < 2 or b"> Second choice" not in output:
            read_output()
            if time.monotonic() >= deadline:
                raise RuntimeError("resized menu was not redrawn: " + repr(output))
    action = {"enter": b"\n", "resize": b"\n", "resize-exit": b"\n", "down": b"\x1b[B\n", "up": b"\x1b[A\n", "j": b"j\n", "escape": b"\x1b", "q": b"q", "cancel": b"q", "interrupt": b"\x03", "eof": b"\x04"}.get(sys.argv[2])
    if action is not None:
        os.write(terminal, action)
    deadline = time.monotonic() + 3
    while True:
        read_output()
        exited, status = os.waitpid(pid, os.WNOHANG)
        if exited:
            reaped = True
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("menu needed extra input to exit: " + repr(output))
    restored = termios.tcgetattr(terminal)
    if restored != original:
        raise RuntimeError("terminal mode was not restored: " + repr((original, restored)))
    if sys.argv[2] == "resize-exit" and b"\x1b[4A" in output:
        raise RuntimeError("resized cleanup erased unknown prior rows: " + repr(output))
    if os.waitstatus_to_exitcode(status) != 0 or b"PTY_EXPECTED_CHOICE_RESULT" not in output or b"\x1b[?25h" not in output:
        raise RuntimeError("terminal result failed: " + repr(output))
finally:
    if not reaped:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except ProcessLookupError:
            pass
    os.close(terminal)
`
	for _, action := range []string{"enter", "down", "up", "j", "escape", "q", "cancel", "interrupt", "timeout", "eof", "resize", "resize-exit"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, python, "-c", harness, executable, action)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("real PTY selection: %v\n%s", err, output)
			}
		})
	}
}
