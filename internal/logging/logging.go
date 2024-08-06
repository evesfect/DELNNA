package logging

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger *zap.SugaredLogger

func InitLogger(logFile string, debug bool) {
	// Lumberjack for log rotation
	lumber := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    100, // megabytes
		MaxBackups: 3,
		MaxAge:     28, // days
		Compress:   true,
	}

	// Custom timestamp format
	customTimeEncoder := func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05.000"))
	}

	// Custom level encoder w/ colorized output
	customLevelEncoder := func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		switch level {
		case zapcore.DebugLevel:
			enc.AppendString("\x1b[36mDEBUG\x1b[0m") // Cyan
		case zapcore.InfoLevel:
			enc.AppendString("\x1b[32mINFO\x1b[0m") // Green
		case zapcore.WarnLevel:
			enc.AppendString("\x1b[33mWARN\x1b[0m") // Yellow
		case zapcore.ErrorLevel:
			enc.AppendString("\x1b[31mERROR\x1b[0m") // Red
		case zapcore.DPanicLevel:
			enc.AppendString("\x1b[35mDPANIC\x1b[0m") // Magenta
		case zapcore.PanicLevel:
			enc.AppendString("\x1b[35mPANIC\x1b[0m") // Magenta
		case zapcore.FatalLevel:
			enc.AppendString("\x1b[35mFATAL\x1b[0m") // Magenta
		}
	}

	// Define log level
	logLevel := zapcore.InfoLevel
	if debug {
		logLevel = zapcore.DebugLevel
	}

	// Create encoder configuration
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    customLevelEncoder,
		EncodeTime:     customTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create core for console output
	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		logLevel,
	)

	// Create core for file output
	fileCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(lumber),
		logLevel,
	)

	// Combine cores
	core := zapcore.NewTee(consoleCore, fileCore)

	// Create logger
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	logger = zapLogger.Sugar()
}

// Debug logs a debug message
func Debug(msg string, keysAndValues ...interface{}) {
	logger.Debugw(msg, addCallerInfo(keysAndValues...)...)
}

// Info logs an info message
func Info(msg string, keysAndValues ...interface{}) {
	logger.Infow(msg, addCallerInfo(keysAndValues...)...)
}

// Warn logs a warning message
func Warn(msg string, keysAndValues ...interface{}) {
	logger.Warnw(msg, addCallerInfo(keysAndValues...)...)
}

// Error logs an error message
func Error(msg string, keysAndValues ...interface{}) {
	logger.Errorw(msg, addCallerInfo(keysAndValues...)...)
}

// Fatal logs a fatal message and exits the program
func Fatal(msg string, keysAndValues ...interface{}) {
	logger.Fatalw(msg, addCallerInfo(keysAndValues...)...)
}

// addCallerInfo adds file and line information to the log message
func addCallerInfo(keysAndValues ...interface{}) []interface{} {
	_, file, line, ok := runtime.Caller(2)
	if ok {
		keysAndValues = append(keysAndValues, "file", filepath.Base(file), "line", line)
	}
	return keysAndValues
}

// LogHTTPRequest logs incoming HTTP requests
func LogHTTPRequest(method, url, remoteAddr string, statusCode int, duration time.Duration) {
	Info("HTTP Request",
		"method", method,
		"url", url,
		"remote_addr", remoteAddr,
		"status_code", statusCode,
		"duration", duration,
	)
}

// LogNodeRegistration logs node registration events
func LogNodeRegistration(nodeID, address string, success bool) {
	if success {
		Info("Node registered successfully",
			"node_id", nodeID,
			"address", address,
		)
	} else {
		Warn("Node registration failed",
			"node_id", nodeID,
			"address", address,
		)
	}
}

// LogNodeAuthentication logs node authentication events
func LogNodeAuthentication(nodeID string, success bool) {
	if success {
		Info("Node authenticated successfully",
			"node_id", nodeID,
		)
	} else {
		Warn("Node authentication failed",
			"node_id", nodeID,
		)
	}
}

// LogTokenRefresh logs token refresh events
func LogTokenRefresh(nodeID string, success bool) {
	if success {
		Info("Token refreshed successfully",
			"node_id", nodeID,
		)
	} else {
		Warn("Token refresh failed",
			"node_id", nodeID,
		)
	}
}

// LogDataAccess logs data access events
func LogDataAccess(nodeID, targetNodeID string, success bool) {
	if success {
		Info("Data access successful",
			"node_id", nodeID,
			"target_node_id", targetNodeID,
		)
	} else {
		Warn("Data access failed",
			"node_id", nodeID,
			"target_node_id", targetNodeID,
		)
	}
}

// LogDataUpdate logs data update events
func LogDataUpdate(nodeID string, success bool) {
	if success {
		Info("Data updated successfully",
			"node_id", nodeID,
		)
	} else {
		Warn("Data update failed",
			"node_id", nodeID,
		)
	}
}
