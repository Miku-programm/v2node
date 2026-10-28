//go:build !linux

package probelog

import "errors"

type capturer interface {
	Close()
	Stats() map[string]any
}

func newCapturer(_ *Recorder, _ string, _ []int, _ string) (capturer, error) {
	return nil, errors.New("packet capture is only supported on linux")
}
