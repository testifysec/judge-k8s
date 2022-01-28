package cmd

import (
	"os"

	"github.com/labstack/gommon/log"
	"github.com/sirupsen/logrus"
)

type logrusLogger struct {
	l *logrus.Logger
}

func newLogger() *logrusLogger {
	l := logrus.New()
	l.Out = os.Stderr
	f := &logrus.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		DisableTimestamp:       true,
	}

	l.SetFormatter(f)
	return &logrusLogger{l}
}

func (l *logrusLogger) SetLevel(levelStr string) error {
	level, err := logrus.ParseLevel(levelStr)
	if err != nil {
		return err
	}

	l.l.SetLevel(level)
	return nil
}

func (l *logrusLogger) Errorf(format string, args ...interface{}) {
	l.l.Errorf(format, args...)
}

func (l *logrusLogger) Error(args ...interface{}) {
	l.l.Error(args...)
}

func (l *logrusLogger) Warnf(format string, args ...interface{}) {
	l.l.Warnf(format, args...)
}

func (l *logrusLogger) Warn(args ...interface{}) {
	l.l.Warn(args...)
}

func (l *logrusLogger) Debugf(format string, args ...interface{}) {
	l.l.Debugf(format, args...)
}

func (l *logrusLogger) Debug(args ...interface{}) {
	l.l.Debug(args...)
}

func (l *logrusLogger) Infof(format string, args ...interface{}) {
	l.l.Infof(format, args...)
}

func (l *logrusLogger) Info(args ...interface{}) {
	l.l.Info(args...)
}

func (l *logrusLogger) Debugj(j log.JSON) {
	l.l.Debug(j)
}
