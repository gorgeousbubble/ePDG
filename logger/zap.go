package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"path/filepath"
	"time"
)

// LogLevel log level user define
type LogLevel string

const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
	PanicLevel LogLevel = "panic"
	FatalLevel LogLevel = "fatal"
)

// Config log configure structure
type Config struct {
	Level      LogLevel `yaml:"level" json:"level"`           // log level
	Filename   string   `yaml:"filename" json:"filename"`     // log file path
	MaxSize    int      `yaml:"maxSize" json:"maxSize"`       // single file maximum size (MB)
	MaxBackups int      `yaml:"maxBackups" json:"maxBackups"` // maximum backups number
	MaxAge     int      `yaml:"maxAge" json:"maxAge"`         // maximum age
	Compress   bool     `yaml:"compress" json:"compress"`     // compress backups
	Console    bool     `yaml:"console" json:"console"`       // output console
}

var (
	globalLogger *zap.SugaredLogger
)

// Init global logger
func Init(cfg Config) error {
	// set logger level
	logLevel := mapLogLevel(cfg.Level)
	if logLevel == zapcore.InvalidLevel {
		logLevel = zapcore.InfoLevel
	}
	// create zap core
	var cores []zapcore.Core
	// output file core
	if cfg.Filename != "" {
		// make sure log folder existed
		if err := os.MkdirAll(filepath.Dir(cfg.Filename), 0755); err != nil {
			return err
		}
		// create sync logger
		fileWriter := zapcore.AddSync(&lumberjack.Logger{
			Filename:   cfg.Filename,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		})
		// create new zap core
		fileCore := zapcore.NewCore(
			getJSONEncoder(),
			fileWriter,
			logLevel,
		)
		cores = append(cores, fileCore)
	}
	// console output
	if cfg.Console {
		consoleCore := zapcore.NewCore(
			getConsoleEncoder(),
			zapcore.Lock(os.Stdout),
			logLevel,
		)
		cores = append(cores, consoleCore)
	}
	// create multiple core tree
	core := zapcore.NewTee(cores...)
	// create logger with debug information
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	defer logger.Sync()
	// create SugaredLogger
	globalLogger = logger.Sugar()
	return nil
}

// getJSONEncoder get Json encoder
func getJSONEncoder() zapcore.Encoder {
	return zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})
}

// getConsoleEncoder get console encoder
func getConsoleEncoder() zapcore.Encoder {
	return zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		TimeKey:        "T",
		LevelKey:       "L",
		NameKey:        "N",
		CallerKey:      "C",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "M",
		StacktraceKey:  "S",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     customTimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})
}

// customTimeEncoder timestamp defined
func customTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05.000"))
}

// mapLogLevel map log level
func mapLogLevel(level LogLevel) zapcore.Level {
	switch level {
	case DebugLevel:
		return zapcore.DebugLevel
	case InfoLevel:
		return zapcore.InfoLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	case PanicLevel:
		return zapcore.PanicLevel
	case FatalLevel:
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// Logger get global logger
func Logger() *zap.SugaredLogger {
	if globalLogger == nil {
		err := Init(Config{
			Level:    InfoLevel,
			Console:  true,
			Filename: "./logs/app.log",
			MaxSize:  100,
			MaxAge:   7,
		})
		if err != nil {
			return nil
		}
	}
	return globalLogger
}

func Debug(args ...interface{}) {
	Logger().Debug(args...)
}

func Debugf(template string, args ...interface{}) {
	Logger().Debugf(template, args...)
}

func Info(args ...interface{}) {
	Logger().Info(args...)
}

func Infof(template string, args ...interface{}) {
	Logger().Infof(template, args...)
}

func Warn(args ...interface{}) {
	Logger().Warn(args...)
}

func Warnf(template string, args ...interface{}) {
	Logger().Warnf(template, args...)
}

func Error(args ...interface{}) {
	Logger().Error(args...)
}

func Errorf(template string, args ...interface{}) {
	Logger().Errorf(template, args...)
}

func Panic(args ...interface{}) {
	Logger().Panic(args...)
}

func Panicf(template string, args ...interface{}) {
	Logger().Panicf(template, args...)
}

func Fatal(args ...interface{}) {
	Logger().Fatal(args...)
}

func Fatalf(template string, args ...interface{}) {
	Logger().Fatalf(template, args...)
}

func With(fields ...interface{}) *zap.SugaredLogger {
	return Logger().With(fields...)
}
