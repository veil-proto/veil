package ratelog

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestLimiter_SuppressesBurstsWithinInterval(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	origFlags := log.Flags()
	log.SetFlags(0)
	defer log.SetFlags(origFlags)

	l := NewLimiter(50 * time.Millisecond)
	for i := 0; i < 100; i++ {
		l.Printf("hostile input from %d", i)
	}

	lines := strings.Count(buf.String(), "\n")
	if lines != 1 {
		t.Fatalf("expected exactly 1 emitted line for a burst within one interval, got %d:\n%s", lines, buf.String())
	}
	if !strings.Contains(buf.String(), "hostile input from 0") {
		t.Fatalf("expected the first message in the burst to be the one emitted, got: %s", buf.String())
	}
}

func TestLimiter_EmitsAgainAfterInterval(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	origFlags := log.Flags()
	log.SetFlags(0)
	defer log.SetFlags(origFlags)

	l := NewLimiter(10 * time.Millisecond)
	l.Printf("first")
	time.Sleep(20 * time.Millisecond)
	l.Printf("second")

	lines := strings.Count(buf.String(), "\n")
	if lines != 2 {
		t.Fatalf("expected 2 emitted lines across two intervals, got %d:\n%s", lines, buf.String())
	}
}

func TestLimiter_ReportsSuppressedCount(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	origFlags := log.Flags()
	log.SetFlags(0)
	defer log.SetFlags(origFlags)

	l := NewLimiter(20 * time.Millisecond)
	l.Printf("first")
	l.Printf("suppressed-1")
	l.Printf("suppressed-2")
	time.Sleep(30 * time.Millisecond)
	l.Printf("third")

	if !strings.Contains(buf.String(), "+2 similar messages suppressed") {
		t.Fatalf("expected the suppressed count to be folded into the next emitted line, got: %s", buf.String())
	}
}
