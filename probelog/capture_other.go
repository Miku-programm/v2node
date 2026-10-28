//go:build !linux

package probelog

import "errors"

type capturer interface {
	Close()
}

func newCapturer(_ *Recorder, _ string, _ []int) (capturer, error) {
	return nil, errors.New("packet capture is only supported on linux")
}
