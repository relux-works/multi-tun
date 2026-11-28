package vpncore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// All files and the user database projection belong to this temporary fixture.
func openConnectFixture(t *testing.T) (OpenConnectStartRequest, string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldLookup := lookupUserVPNCore
	lookupUserVPNCore = func(uid string) (*user.User, error) {
		if uid != strconv.Itoa(os.Getuid()) {
			return nil, errors.New("unexpected user")
		}
		return &user.User{Uid: uid, HomeDir: home}, nil
	}
	t.Cleanup(func() { lookupUserVPNCore = oldLookup })
	for _, dir := range []string{".cache/openconnect-tun/sessions", ".cache/openconnect-tun/runtime", ".local/bin"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(home, ".cache/openconnect-tun/sessions/script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return OpenConnectStartRequest{ServerURL: "https://vpn.example.test/outside", Protocol: "anyconnect", ScriptPath: script, PIDFilePath: filepath.Join(home, ".cache/openconnect-tun/runtime/openconnect.pid"), Cookie: "COOKIE_TEST_SECRET", UserAgent: "Client 1.0", OS: "mac-intel", VersionString: "1.0", LocalHostname: "test-host"}, home
}

func TestOpenConnectStartValidationMatrix(t *testing.T) {
	base, _ := openConnectFixture(t)
	for _, test := range []struct {
		name   string
		change func(*OpenConnectStartRequest)
		valid  bool
	}{
		{"normal", func(*OpenConnectStartRequest) {}, true},
		{"default protocol", func(r *OpenConnectStartRequest) { r.Protocol = "" }, true},
		{"no pid", func(r *OpenConnectStartRequest) { r.PIDFilePath = "" }, true},
		{"ipv6", func(r *OpenConnectStartRequest) { r.ServerURL = "https://[2001:db8::1]:444/group" }, true},
		{"cookie limit", func(r *OpenConnectStartRequest) { r.Cookie = strings.Repeat("x", 16*1024) }, true},
		{"identity limit", func(r *OpenConnectStartRequest) { r.UserAgent = strings.Repeat("x", 128) }, true},
		{"http", func(r *OpenConnectStartRequest) { r.ServerURL = "http://vpn.example.test" }, false},
		{"empty host", func(r *OpenConnectStartRequest) { r.ServerURL = "https:///path" }, false},
		{"relative server", func(r *OpenConnectStartRequest) { r.ServerURL = "vpn.example.test" }, false},
		{"userinfo", func(r *OpenConnectStartRequest) { r.ServerURL = "https://user:password@vpn.example.test" }, false},
		{"fragment", func(r *OpenConnectStartRequest) { r.ServerURL += "#fragment" }, false},
		{"empty fragment", func(r *OpenConnectStartRequest) { r.ServerURL += "#" }, false},
		{"space", func(r *OpenConnectStartRequest) { r.ServerURL += " bad" }, false},
		{"url newline", func(r *OpenConnectStartRequest) { r.ServerURL += "\n" }, false},
		{"protocol", func(r *OpenConnectStartRequest) { r.Protocol = "nc" }, false},
		{"empty cookie", func(r *OpenConnectStartRequest) { r.Cookie = "" }, false},
		{"oversized cookie", func(r *OpenConnectStartRequest) { r.Cookie = strings.Repeat("x", 16*1024+1) }, false},
		{"cookie LF", func(r *OpenConnectStartRequest) { r.Cookie += "\n--script=/tmp/evil" }, false},
		{"cookie CR", func(r *OpenConnectStartRequest) { r.Cookie += "\r" }, false},
		{"cookie NUL", func(r *OpenConnectStartRequest) { r.Cookie += "\x00" }, false},
		{"identity newline", func(r *OpenConnectStartRequest) { r.OS = "mac\n--foo" }, false},
		{"identity nonascii", func(r *OpenConnectStartRequest) { r.VersionString = "å" }, false},
		{"identity DEL", func(r *OpenConnectStartRequest) { r.LocalHostname = "host\x7f" }, false},
		{"identity too long", func(r *OpenConnectStartRequest) { r.UserAgent = strings.Repeat("x", 129) }, false},
		{"script empty", func(r *OpenConnectStartRequest) { r.ScriptPath = "" }, false},
		{"script relative", func(r *OpenConnectStartRequest) { r.ScriptPath = "script.sh" }, false},
		{"script dirty", func(r *OpenConnectStartRequest) { r.ScriptPath = filepath.Dir(r.ScriptPath) + "/../sessions/script.sh" }, false},
		{"script outside", func(r *OpenConnectStartRequest) { r.ScriptPath = "/bin/sh" }, false},
		{"script prefix sibling", func(r *OpenConnectStartRequest) {
			r.ScriptPath = strings.Replace(r.ScriptPath, "/sessions/", "/sessions-evil/", 1)
		}, false},
		{"pid relative", func(r *OpenConnectStartRequest) { r.PIDFilePath = "openconnect.pid" }, false},
		{"pid outside", func(r *OpenConnectStartRequest) { r.PIDFilePath = "/tmp/openconnect.pid" }, false},
		{"pid traversal", func(r *OpenConnectStartRequest) {
			r.PIDFilePath = filepath.Dir(r.PIDFilePath) + "/../runtime/openconnect.pid"
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := base
			test.change(&req)
			err := validateOpenConnectStart(req, os.Getuid())
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), req.Cookie) && req.Cookie != "" {
				t.Fatal("validation disclosed cookie")
			}
		})
	}
}

func TestOpenConnectFilesystemRefusals(t *testing.T) {
	for _, kind := range []string{"script symlink", "script writable", "script directory", "script missing", "parent symlink", "pid symlink", "pid parent symlink", "pid directory", "pid writable", "valid local bin"} {
		t.Run(kind, func(t *testing.T) {
			req, home := openConnectFixture(t)
			switch kind {
			case "script symlink":
				target := filepath.Join(home, "script")
				if err := os.Rename(req.ScriptPath, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, req.ScriptPath); err != nil {
					t.Fatal(err)
				}
			case "script writable":
				if err := os.Chmod(req.ScriptPath, 0o722); err != nil {
					t.Fatal(err)
				}
			case "script directory":
				req.ScriptPath = filepath.Dir(req.ScriptPath)
			case "script missing":
				req.ScriptPath += "missing"
			case "parent symlink":
				parent := filepath.Dir(req.ScriptPath)
				if err := os.Rename(parent, parent+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+"-real", parent); err != nil {
					t.Fatal(err)
				}
			case "pid symlink":
				if err := os.Symlink(req.ScriptPath, req.PIDFilePath); err != nil {
					t.Fatal(err)
				}
			case "pid parent symlink":
				parent := filepath.Dir(req.PIDFilePath)
				if err := os.Rename(parent, parent+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+"-real", parent); err != nil {
					t.Fatal(err)
				}
			case "pid directory":
				if err := os.Mkdir(req.PIDFilePath, 0o700); err != nil {
					t.Fatal(err)
				}
			case "pid writable":
				if err := os.WriteFile(req.PIDFilePath, []byte("0"), 0o666); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(req.PIDFilePath, 0o666); err != nil {
					t.Fatal(err)
				}
			case "valid local bin":
				target := filepath.Join(home, ".local/bin/script")
				if err := os.Rename(req.ScriptPath, target); err != nil {
					t.Fatal(err)
				}
				req.ScriptPath = target
			}
			err := validateOpenConnectStart(req, os.Getuid())
			if (err == nil) != (kind == "valid local bin") {
				t.Fatalf("unexpected filesystem validation: %v", err)
			}
		})
	}
}

func TestOpenConnectTypedWireAndFDContract(t *testing.T) {
	for _, test := range []struct {
		name, payload, fd string
		valid             bool
	}{
		{"valid", `{"action":"openconnect.start","openconnect":{"server_url":"https://vpn.example.test","script_path":"/unused","cookie":"secret"}}`, "regular", true},
		{"missing descriptor", `{"action":"openconnect.start","openconnect":{}}`, "", false},
		{"pipe descriptor", `{"action":"openconnect.start","openconnect":{}}`, "pipe", false},
		{"missing payload", `{"action":"openconnect.start"}`, "regular", false},
		{"arbitrary argv", `{"action":"openconnect.start","openconnect":{"command":["/bin/sh"]}}`, "regular", false},
		{"extra outer field", `{"action":"openconnect.start","openconnect":{},"setpgid":true}`, "regular", false},
		{"wrong action", `{"action":"ping","openconnect":{}}`, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, client := unixSocketPair(t)
			var rights []byte
			switch test.fd {
			case "regular":
				file := openSecurityTestLog(t, "typed.log")
				rights = unix.UnixRights(int(file.Fd()))
			case "pipe":
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				defer writer.Close()
				rights = unix.UnixRights(int(writer.Fd()))
			}
			writeUnixPayload(t, client, []byte(test.payload+"\n"), rights)
			req, log, err := readRequest(server)
			if log != nil {
				defer log.Close()
			}
			if (err == nil) != test.valid {
				t.Fatalf("wire validity=%v error=%v", test.valid, err)
			}
			if test.valid && (req.OpenConnect == nil || log == nil || safeRequestAction(req.Action) != "openconnect.start") {
				t.Fatal("lost typed payload, descriptor, or diagnostic action")
			}
		})
	}
}

func TestOpenConnectBinaryValidation(t *testing.T) {
	_, home := openConnectFixture(t)
	file := filepath.Join(home, "binary")
	if err := os.WriteFile(file, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateOpenConnectExecutable(file, uint32(os.Getuid()), true); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if err := validateOpenConnectExecutable(file, uint32(os.Getuid()+1), true); err == nil {
			t.Fatal("foreign-owned binary accepted")
		}
	}
	for _, mode := range []os.FileMode{0o722, 0o777, 0o600} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if err := validateOpenConnectExecutable(file, uint32(os.Getuid()), true); err == nil {
			t.Fatalf("binary mode %o accepted", mode)
		}
	}
	link := filepath.Join(home, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := validateOpenConnectExecutable(link, uint32(os.Getuid()), true); err == nil {
		t.Fatal("symlink binary accepted")
	}
}

// A harmless local Go subprocess captures argv/stdin, then blocks until the
// daemon signals its process group. No VPN binary, network or Keychain is used.
func TestOpenConnectOfflineChild(t *testing.T) {
	if os.Getenv("TUNWAVE_OFFLINE_OC_CHILD") != "1" {
		return
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(os.Getenv("TUNWAVE_OFFLINE_OC_STDIN"), data, 0o600); err != nil {
		os.Exit(3)
	}
	for _, arg := range os.Args[3:] {
		if strings.HasPrefix(arg, "--pid-file=") {
			if err := os.WriteFile(strings.TrimPrefix(arg, "--pid-file="), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
				os.Exit(5)
			}
		}
	}
	args, _ := json.Marshal(os.Args[3:])
	if err := os.WriteFile(os.Getenv("TUNWAVE_OFFLINE_OC_ARGS"), args, 0o600); err != nil {
		os.Exit(4)
	}
	fmt.Fprintln(os.Stdout, "offline child stdout")
	fmt.Fprintln(os.Stderr, "offline child stderr")
	for {
		time.Sleep(time.Second)
	}
}

func TestOpenConnectStartRPCSpawnAndSignal(t *testing.T) {
	req, home := openConnectFixture(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	oldBinary, oldOwner, oldCommand := openConnectBinaryVPNCore, openConnectHomebrewUIDVPNCore, execCommandVPNCore
	openConnectBinaryVPNCore = func() (string, error) { return binary, nil }
	openConnectHomebrewUIDVPNCore = func(string) (uint32, error) { return uint32(os.Getuid()), nil }
	stdinPath, argsPath := filepath.Join(home, "stdin"), filepath.Join(home, "argv")
	t.Setenv("TUNWAVE_OFFLINE_OC_CHILD", "1")
	t.Setenv("TUNWAVE_OFFLINE_OC_STDIN", stdinPath)
	t.Setenv("TUNWAVE_OFFLINE_OC_ARGS", argsPath)
	execCommandVPNCore = func(name string, args ...string) *exec.Cmd {
		if name != binary {
			t.Fatal("untrusted command")
		}
		return oldCommand(name, append([]string{"-test.run=^TestOpenConnectOfflineChild$", "--"}, args...)...)
	}
	t.Cleanup(func() {
		openConnectBinaryVPNCore, openConnectHomebrewUIDVPNCore, execCommandVPNCore = oldBinary, oldOwner, oldCommand
	})
	cfg, listener := newRPCClientTestListener(t)
	d := newServiceDaemon(cfg, os.Getuid(), os.Getgid())
	withRPCServerIdentity(t, uint32(os.Getuid()), func(*net.UnixConn) (uint32, error) { return uint32(os.Getuid()), nil })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			d.handleConn(conn, d.requests.enqueue())
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	logPath := filepath.Join(home, "client.log")
	pid, handle, err := StartOpenConnect(cfg, req, logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, ok := d.children.get(handle); ok {
			_, _ = d.children.signal(handle, syscall.SIGKILL)
		}
	})
	child, ok := d.children.get(handle)
	if !ok || child.pid != pid || !child.setPGID || child.kind != "openconnect" {
		t.Fatal("child not tracked with exact pid and group")
	}
	deadline := time.Now().Add(3 * time.Second)
	var args []string
	for {
		raw, readErr := os.ReadFile(argsPath)
		if readErr == nil {
			if err := json.Unmarshal(raw, &args); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("offline child did not publish args")
		}
		time.Sleep(time.Millisecond)
	}
	expected := []string{"--cookie-on-stdin", "--protocol=anyconnect", "--pid-file=" + req.PIDFilePath, "--useragent", "Client 1.0", "--os", "mac-intel", "--version-string", "1.0", "--local-hostname", "test-host", "--script", req.ScriptPath, "https://vpn.example.test/outside"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("wrong launch argv: %v", args)
	}
	witnessPID, err := os.ReadFile(req.PIDFilePath)
	if err != nil || string(witnessPID) != strconv.Itoa(pid) {
		t.Fatal("returned pid differs from the child's own pid")
	}
	group, err := syscall.Getpgid(pid)
	if err != nil || group != pid {
		t.Fatal("spawned child is not its own process group leader")
	}
	for _, arg := range args {
		if strings.Contains(arg, req.Cookie) || arg == "--background" {
			t.Fatal("cookie leaked to argv or child backgrounded")
		}
	}
	raw, err := os.ReadFile(stdinPath)
	if err != nil || string(raw) != req.Cookie+"\n" {
		t.Fatal("cookie did not reach stdin intact")
	}
	if _, err := Signal(cfg, "unissued-handle", "-TERM"); err == nil {
		t.Fatal("forged child handle accepted")
	}
	if _, err := Signal(cfg, handle, "-TERM"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		if _, ok := d.children.get(handle); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child not reaped after TERM")
		}
		time.Sleep(time.Millisecond)
	}
	raw, err = os.ReadFile(logPath)
	if err != nil || strings.Contains(string(raw), req.Cookie) || !strings.Contains(string(raw), "offline child stdout") || !strings.Contains(string(raw), "offline child stderr") {
		t.Fatal("passed log missing output or disclosed cookie")
	}
	if _, err := Signal(cfg, handle, "-KILL"); err == nil {
		t.Fatal("consumed handle accepted")
	}
}

func TestOpenConnectSpawnRefusalsDoNotDiscloseCookie(t *testing.T) {
	req, _ := openConnectFixture(t)
	d := newServiceDaemon(ServiceConfig{}, os.Getuid(), os.Getgid())
	log := openSecurityTestLog(t, "refused.log")
	oldBinary, oldOwner, oldCommand := openConnectBinaryVPNCore, openConnectHomebrewUIDVPNCore, execCommandVPNCore
	defer func() {
		openConnectBinaryVPNCore, openConnectHomebrewUIDVPNCore, execCommandVPNCore = oldBinary, oldOwner, oldCommand
	}()
	for _, kind := range []string{"invalid cookie", "missing binary", "binary resolver error", "spawn failure"} {
		t.Run(kind, func(t *testing.T) {
			request := req
			switch kind {
			case "invalid cookie":
				request.Cookie += "\n"
			case "missing binary":
				openConnectBinaryVPNCore = func() (string, error) { return "/nonexistent/openconnect", nil }
			case "binary resolver error":
				openConnectBinaryVPNCore = func() (string, error) { return "", errors.New(req.Cookie) }
			case "spawn failure":
				binary, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				binary, err = filepath.EvalSymlinks(binary)
				if err != nil {
					t.Fatal(err)
				}
				openConnectBinaryVPNCore = func() (string, error) { return binary, nil }
				openConnectHomebrewUIDVPNCore = func(string) (uint32, error) { return uint32(os.Getuid()), nil }
				execCommandVPNCore = func(string, ...string) *exec.Cmd { return exec.Command("/missing/" + req.Cookie) }
			}
			pid, handle, err := d.handleOpenConnectStart(Request{OpenConnect: &request}, log)
			if err == nil || pid != 0 || handle != "" || strings.Contains(err.Error(), req.Cookie) {
				t.Fatal("invalid start spawned child or disclosed cookie")
			}
		})
	}
}

func TestOpenConnectScriptArgumentPreservesLiteralFilename(t *testing.T) {
	req, home := openConnectFixture(t)
	req.ScriptPath = filepath.Join(home, ".local/bin/script ' ; echo forbidden")
	if err := os.WriteFile(req.ScriptPath, []byte("#!/bin/sh\nprintf literal-script"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateOpenConnectStart(req, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	args := openConnectArgs(req)
	// Execute the command string with an inert local script, matching --script's
	// shell semantics. A missing quote would split the name or execute punctuation.
	script := args[len(args)-2]
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	if err != nil || string(out) != "literal-script" {
		t.Fatalf("literal script filename changed: %v", err)
	}
}

func TestOpenConnectOldDaemonFieldRefusalSupportsSafeFallback(t *testing.T) {
	for _, message := range []string{`json: unknown field "openconnect"`, `json: unknown field "other"`, "typed launch refused"} {
		t.Run(message, func(t *testing.T) {
			cfg, listener := newRPCClientTestListener(t)
			withRPCServerIdentity(t, uint32(os.Getuid()), func(*net.UnixConn) (uint32, error) { return uint32(os.Getuid()), nil })
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 2; i++ {
					conn, err := listener.AcceptUnix()
					if err != nil {
						done <- err
						return
					}
					request, log, err := readRequest(conn)
					if log != nil {
						_ = log.Close()
					}
					if err != nil {
						_ = conn.Close()
						done <- err
						return
					}
					want := "proc.ensure"
					reply := `json: unknown field "proc_ensure"`
					if i == 1 {
						want = "openconnect.start"
						reply = message
					}
					if request.Action != want {
						_ = conn.Close()
						done <- fmt.Errorf("action=%s, want %s", request.Action, want)
						return
					}
					err = writeResponse(conn, Response{Error: reply})
					_ = conn.Close()
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			_, _, err := StartOpenConnect(cfg, OpenConnectStartRequest{Cookie: "COOKIE_TEST_SECRET"}, filepath.Join(t.TempDir(), "client.log"))
			if serverErr := <-done; serverErr != nil {
				t.Fatal(serverErr)
			}
			var refused *RefusedError
			if !errors.As(err, &refused) {
				t.Fatalf("explicit refusal lost: %v", err)
			}
			if message == `json: unknown field "openconnect"` {
				if !strings.Contains(err.Error(), "unsupported vpn core action") {
					t.Fatal("old helper refusal not recognized")
				}
			} else if err.Error() != message {
				t.Fatal("unrelated refusal converted to retryable unsupported action")
			}
		})
	}
}
