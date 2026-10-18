package vpncore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDaemonVerificationFailureOccursBeforeListen(t *testing.T) {
	// This proves daemon self-verification is the first startup gate, before socket directory creation or listen.
	sentinel := errors.New("verification sentinel")
	socketDir := filepath.Join(t.TempDir(), "not-created")
	d := newServiceDaemon(ServiceConfig{SocketPath: filepath.Join(socketDir, "vpn-core.sock")}, 501, 20)
	d.verify = func() error { return sentinel }
	d.peerUID = func(*net.UnixConn) (uint32, error) { return 501, nil }
	err := d.serve()
	if !errors.Is(err, sentinel) {
		t.Fatalf("serve() error = %v, want verification sentinel", err)
	}
	if _, statErr := os.Stat(socketDir); !os.IsNotExist(statErr) {
		t.Fatalf("socket directory was touched before verification: %v", statErr)
	}
}

func TestPeerUID501IsAcceptedAndSmallRequestIsServed(t *testing.T) {
	// This proves the configured client uid passes peer authorization and a bounded ping reaches request processing.
	server, client := unixSocketPair(t)
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	d.peerUID = func(*net.UnixConn) (uint32, error) { return 501, nil }
	d.acceptConnection(server)
	writeUnixPayload(t, client, []byte("{\"action\":\"ping\"}\n"), nil)
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.OK || response.HelperSnapshot == nil {
		t.Fatalf("response = %#v, want successful ping", response)
	}
}

func TestPeerUID502IsRefusedWithoutRequestProcessing(t *testing.T) {
	// This proves an unconfigured non-root peer is rejected before a request is decoded or tracked.
	server, client := unixSocketPair(t)
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	d.peerUID = func(*net.UnixConn) (uint32, error) { return 502, nil }
	d.acceptConnection(server)
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("decode refusal: %v", err)
	}
	if response.OK || !strings.Contains(response.Error, "not authorized") {
		t.Fatalf("response = %#v, want uid refusal", response)
	}
	snapshot := d.requests.snapshot()
	if len(snapshot.ActiveRequests) != 0 || len(snapshot.QueuedRequests) != 0 {
		t.Fatalf("unauthorized request reached tracker: %#v", snapshot)
	}
}

func TestReadRequestRefusesOversizedPayload(t *testing.T) {
	// This proves payloads beyond 1 MiB are rejected rather than decoded or dispatched.
	server, client := unixSocketPair(t)
	errCh := make(chan error, 1)
	go func() {
		_, _, err := readRequest(server)
		errCh <- err
	}()
	payload := append(bytes.Repeat([]byte{'x'}, maxRequestBytesVPNCore+1), '\n')
	go func() { _, _ = client.Write(payload) }()
	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readRequest() error = %v, want oversized refusal", err)
	}
}

func TestReadRequestRefusesLogPathField(t *testing.T) {
	// This proves the removed path-based logging field is rejected as unknown JSON.
	server, client := unixSocketPair(t)
	writeUnixPayload(t, client, []byte("{\"action\":\"run\",\"log_path\":\"/tmp/root-write\"}\n"), nil)
	_, _, err := readRequest(server)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("readRequest() error = %v, want unknown log_path refusal", err)
	}
}

func TestReadRequestRefusesNonRegularLogFD(t *testing.T) {
	// This proves SCM_RIGHTS cannot smuggle a pipe in place of the required regular client-owned log file.
	server, client := unixSocketPair(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	request := []byte("{\"action\":\"run\",\"command\":[\"/bin/sh\",\"-c\",\"true\"]}\n")
	writeUnixPayload(t, client, request, unix.UnixRights(int(writer.Fd())))
	_, _, err = readRequest(server)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("readRequest() error = %v, want non-regular fd refusal", err)
	}
}

func TestReadRequestAcceptsRegularLogFD(t *testing.T) {
	// This proves a client-opened regular append file is accepted with FD_CLOEXEC set on the received descriptor.
	server, client := unixSocketPair(t)
	path := t.TempDir() + "/client.log"
	logFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	request := []byte("{\"action\":\"run\",\"command\":[\"/bin/sh\",\"-c\",\"true\"]}\n")
	writeUnixPayload(t, client, request, unix.UnixRights(int(logFile.Fd())))
	decoded, received, err := readRequest(server)
	if err != nil {
		t.Fatalf("readRequest() error = %v", err)
	}
	defer received.Close()
	if decoded.Action != "run" || received == nil {
		t.Fatalf("decoded = %#v, fd=%v", decoded, received)
	}
	flags, err := unix.FcntlInt(received.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("received log fd is missing close-on-exec")
	}
}

func TestReadRequestWaitDoesNotBlockConcurrentCommandStart(t *testing.T) {
	// This proves an EAGAIN wait releases ForkLock so a concurrent command can start before the slow client sends data.
	server, client := unixSocketPair(t)
	if err := server.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	previousRecvmsg := recvmsgVPNCore
	firstRecv := true
	waiting := make(chan struct{})
	recvmsgVPNCore = func(fd int, p, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
		if firstRecv {
			firstRecv = false
			close(waiting)
			return 0, 0, 0, nil, unix.EAGAIN
		}
		return unix.Recvmsg(fd, p, oob, flags)
	}
	t.Cleanup(func() { recvmsgVPNCore = previousRecvmsg })

	readDone := make(chan error, 1)
	go func() {
		_, _, err := readRequest(server)
		readDone <- err
	}()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("reader did not enter the nonblocking recvmsg callback")
	}

	cmd := exec.Command("/usr/bin/true")
	startDone := make(chan error, 1)
	go func() { startDone <- cmd.Start() }()
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("cmd.Start() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cmd.Start() blocked while readRequest waited for socket readability")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cmd.Wait() error = %v", err)
	}
	writeUnixPayload(t, client, []byte("{\"action\":\"ping\"}\n"), nil)
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("readRequest() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("readRequest() did not finish after the client sent its request")
	}
}

func TestReadRequestImmediatelyRefusesAndClosesMultipleFDs(t *testing.T) {
	// This proves two descriptors, whether coalesced or split across ancillary messages, are both closed at the second descriptor and the request is refused.
	for _, split := range []bool{false, true} {
		t.Run(map[bool]string{false: "one-message", true: "two-messages"}[split], func(t *testing.T) {
			server, client := unixSocketPair(t)
			readers := make([]*os.File, 0, 2)
			writers := make([]*os.File, 0, 2)
			for range 2 {
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				readers = append(readers, reader)
				writers = append(writers, writer)
				t.Cleanup(func() { _ = reader.Close() })
			}
			request := []byte("{\"action\":\"run\",\"command\":[\"/bin/sh\",\"-c\",\"true\"]}\n")
			if split {
				writeUnixPayload(t, client, request[:10], unix.UnixRights(int(writers[0].Fd())))
				writeUnixPayload(t, client, request[10:], unix.UnixRights(int(writers[1].Fd())))
			} else {
				rights := unix.UnixRights(int(writers[0].Fd()), int(writers[1].Fd()))
				writeUnixPayload(t, client, request, rights)
			}
			for _, writer := range writers {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err := readRequest(server)
			if err == nil || !strings.Contains(err.Error(), "more than one") {
				t.Fatalf("readRequest() error = %v, want multiple-fd refusal", err)
			}
			for index, reader := range readers {
				if err := unix.SetNonblock(int(reader.Fd()), true); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1)
				n, readErr := reader.Read(buffer)
				if n != 0 || readErr != io.EOF {
					t.Fatalf("pipe %d read = (%d, %v), want EOF after received fd close", index, n, readErr)
				}
			}
		})
	}
}

func TestHandleConnBoundsSlowClientWithReadDeadline(t *testing.T) {
	// This proves a client that never completes one JSON request is abandoned at the server read deadline.
	previous := serverReadDeadlineVPNCore
	serverReadDeadlineVPNCore = 20 * time.Millisecond
	t.Cleanup(func() { serverReadDeadlineVPNCore = previous })
	server, client := unixSocketPair(t)
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	requestID := d.requests.enqueue()
	done := make(chan struct{})
	go func() {
		d.handleConn(server, requestID)
		close(done)
	}()
	if _, err := client.Write([]byte("{\"action\":")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("slow request was not bounded")
	}
}

func TestConnectionCapRefusesSeventeenthConnection(t *testing.T) {
	// This proves the seventeenth concurrent accepted peer is refused without consuming an unbounded handler slot.
	server, client := unixSocketPair(t)
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	d.peerUID = func(*net.UnixConn) (uint32, error) { return 501, nil }
	for range maxConcurrentConnections {
		d.connections <- struct{}{}
	}
	d.acceptConnection(server)
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.OK || !strings.Contains(response.Error, "connection limit") {
		t.Fatalf("response = %#v, want connection limit refusal", response)
	}
}

func TestMutatingRequestsSerializeWhilePingRemainsConcurrent(t *testing.T) {
	// This proves a second mutation stays queued behind the first while ping is served without taking the mutation lock.
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	firstServer, firstClient := unixSocketPair(t)
	firstLog := openSecurityTestLog(t, "first.log")
	firstID := d.requests.enqueue()
	go d.handleConn(firstServer, firstID)
	writeUnixPayload(t, firstClient, []byte("{\"action\":\"run\",\"command\":[\"/bin/sh\",\"-c\",\"sleep 0.15\"]}\n"), unix.UnixRights(int(firstLog.Fd())))
	waitForActiveAction(t, d, "run")

	secondServer, secondClient := unixSocketPair(t)
	secondLog := openSecurityTestLog(t, "second.log")
	secondID := d.requests.enqueue()
	go d.handleConn(secondServer, secondID)
	writeUnixPayload(t, secondClient, []byte("{\"action\":\"run\",\"command\":[\"/bin/sh\",\"-c\",\"true\"]}\n"), unix.UnixRights(int(secondLog.Fd())))

	pingServer, pingClient := unixSocketPair(t)
	pingID := d.requests.enqueue()
	go d.handleConn(pingServer, pingID)
	writeUnixPayload(t, pingClient, []byte("{\"action\":\"ping\"}\n"), nil)
	if err := pingClient.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var ping Response
	if err := json.NewDecoder(pingClient).Decode(&ping); err != nil {
		t.Fatalf("ping blocked behind mutation: %v", err)
	}
	if !ping.OK || ping.HelperSnapshot == nil || len(ping.HelperSnapshot.QueuedRequests) == 0 {
		t.Fatalf("ping response = %#v, want queued mutation snapshot", ping)
	}
	for _, client := range []*net.UnixConn{firstClient, secondClient} {
		var response Response
		if err := json.NewDecoder(client).Decode(&response); err != nil || !response.OK {
			t.Fatalf("mutation response = %#v, err=%v", response, err)
		}
	}
}

func TestPassedLogWriterKeepsBoundedTail(t *testing.T) {
	// This proves max-lines remains effective on an fd-only log without resolving its filesystem path.
	path := t.TempDir() + "/tail.log"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	writer := newPassedLogWriter(file, 2)
	if _, err := writer.Write([]byte("one\ntwo\nthree\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "two\nthree\n"; got != want {
		t.Fatalf("log tail = %q, want %q", got, want)
	}
}

func TestSignalRefusesForeignPID(t *testing.T) {
	// This proves signal cannot target a process not spawned and tracked by this daemon instance.
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	err := d.handleSignal(Request{PID: os.Getpid(), Signal: "TERM"})
	if err == nil || !strings.Contains(err.Error(), "not spawned") {
		t.Fatalf("handleSignal() error = %v, want foreign pid refusal", err)
	}
}

func TestSpawnedChildCanBeSignalled(t *testing.T) {
	// This proves a live daemon-spawned process group remains an authorized signal target until it is reaped.
	logFile, err := os.OpenFile(t.TempDir()+"/child.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	pid, err := d.handleSpawn(Request{Command: []string{"/bin/sh", "-c", "sleep 30"}, SetPGID: true}, logFile)
	if err != nil {
		t.Fatalf("handleSpawn() error = %v", err)
	}
	defer syscall.Kill(-pid, syscall.SIGKILL)
	if err := d.handleSignal(Request{PID: pid, Signal: "TERM", Group: true}); err != nil {
		t.Fatalf("handleSignal() error = %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := d.children.get(pid); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("spawned pid %d was not reaped", pid)
}

func TestChildRegistryRemovesBeforeReaping(t *testing.T) {
	// This seam-level ordering control proves registry authorization is revoked before the reaping callback can make the PID reusable.
	registry := newChildRegistry()
	registry.add(4242, true)
	registry.removeBeforeReap(4242, func() {
		if _, ok := registry.get(4242); ok {
			t.Fatal("child remained registered when reaping began")
		}
	})
}

func TestSignalAfterChildExitIsRefused(t *testing.T) {
	// This proves kqueue exit observation removes an exited child before a later PID-based signal authorization check.
	logFile := openSecurityTestLog(t, "exited-child.log")
	d := newServiceDaemon(ServiceConfig{}, 501, 20)
	pid, err := d.handleSpawn(Request{Command: []string{"/bin/sh", "-c", "exit 0"}}, logFile)
	if err != nil {
		t.Fatalf("handleSpawn() error = %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := d.children.get(pid); !ok {
			err := d.handleSignal(Request{PID: pid, Signal: "TERM"})
			if err == nil || !strings.Contains(err.Error(), "no longer its child") {
				t.Fatalf("handleSignal() error = %v, want exited-child refusal", err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("exited child pid %d remained registered", pid)
}

func TestInterimAllowlistRefusesArbitraryExecutable(t *testing.T) {
	// This proves PR A rejects arbitrary absolute executables while retaining an explicit positive compatibility control.
	if err := validateInterimCommand([]string{"/usr/bin/id"}); err == nil {
		t.Fatal("validateInterimCommand(/usr/bin/id) error = nil")
	}
	for _, command := range [][]string{{"/usr/sbin/scutil"}, {"/opt/homebrew/bin/sing-box"}, {"/bin/sh", "-c", "true"}} {
		if err := validateInterimCommand(command); err != nil {
			t.Fatalf("validateInterimCommand(%v) error = %v", command, err)
		}
	}
}

func unixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*net.UnixConn, 0, 2)
	for index, fd := range fds {
		file := os.NewFile(uintptr(fd), "vpn-core-test-socket")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			t.Fatalf("socket %d type = %T", index, conn)
		}
		connections = append(connections, unixConn)
	}
	t.Cleanup(func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
	return connections[0], connections[1]
}

func writeUnixPayload(t *testing.T, conn *net.UnixConn, payload, oob []byte) {
	t.Helper()
	written, _, err := conn.WriteMsgUnix(payload, oob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if written < len(payload) {
		if _, err := io.Copy(conn, bytes.NewReader(payload[written:])); err != nil {
			t.Fatal(err)
		}
	}
}

func openSecurityTestLog(t *testing.T, name string) *os.File {
	t.Helper()
	file, err := os.OpenFile(t.TempDir()+"/"+name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func waitForActiveAction(t *testing.T, daemon *serviceDaemon, action string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, active := range daemon.requests.snapshot().ActiveRequests {
			if active.Action == action {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("action %q did not become active", action)
}
