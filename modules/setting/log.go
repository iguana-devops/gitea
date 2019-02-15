// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package setting

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"code.gitea.io/gitea/modules/log"

	"github.com/go-xorm/core"
)

func getLogLevel(section string, key string, defaultValue string) string {
	return Cfg.Section(section).Key(key).In(defaultValue, log.Levels())
}

func newLogService() {
	log.Info("Gitea v%s%s", AppVer, AppBuiltWith)

	LogModes = strings.Split(Cfg.Section("log").Key("MODE").MustString("console"), ",")
	LogConfigs = make([]string, len(LogModes))

	useConsole := false
	for i := 0; i < len(LogModes); i++ {
		LogModes[i] = strings.TrimSpace(LogModes[i])
		if LogModes[i] == "console" {
			useConsole = true
		}
	}

	if !useConsole {
		log.DelLogger("console")
	}

	for i, mode := range LogModes {
		sec, err := Cfg.GetSection("log." + mode)
		if err != nil {
			sec, _ = Cfg.NewSection("log." + mode)
		}

		// Log level.
		levelName := getLogLevel("log."+mode, "LEVEL", LogLevel)
		level := log.FromString(levelName)
		expression := sec.Key("EXPRESSION").MustString("")
		flags := sec.Key("FLAGS").MustInt(0)
		prefix := sec.Key("PREFIX").MustString("")

		baseConfig := fmt.Sprintf(`"level":"%s","expression":"%s","prefix":"%s","flags":%d`, level.String(), expression, prefix, flags)

		// Generate log configuration.
		switch mode {
		case "console":
			LogConfigs[i] = fmt.Sprintf(`{"level":%s}`, level)
		case "router":
			logPath := sec.Key("FILE_NAME").MustString(path.Join(LogRootPath, "access.log"))
			if err = os.MkdirAll(path.Dir(logPath), os.ModePerm); err != nil {
				panic(err.Error())
			}

			LogConfigs[i] = fmt.Sprintf(
				`{"level":%s,"filename":"%s","rotate":%v,"maxsize":%d,"daily":%v,"maxdays":%d,"flags":%d,"prefix":"%s","template":"%s"}`, level,
				logPath,
				sec.Key("LOG_ROTATE").MustBool(true),
				1<<uint(sec.Key("MAX_SIZE_SHIFT").MustInt(28)),
				sec.Key("DAILY_ROTATE").MustBool(true),
				sec.Key("MAX_DAYS").MustInt(7),
				sec.Key("FLAGS").MustInt(-1),
				sec.Key("PREFIX").MustString(""),
				sec.Key("TEMPLATE").MustString("{{.Ctx.RemoteAddr}} - {{.Identity}} {{.Start.Format \"[02/Jan/2006:15:04:05 -0700]\" }} \"{{.Ctx.Req.Method}} {{.Ctx.Req.RequestURI}} {{.Ctx.Req.Proto}}\" {{.ResponseWriter.Status}} {{.ResponseWriter.Size}} \"{{.Ctx.Req.Referer}}\" \"{{.Ctx.Req.UserAgent}}\""))

			log.NewRouterLogger(Cfg.Section("log").Key("BUFFER_LEN").MustInt64(10000), mode, LogConfigs[i])
			log.Info("Router Log: %s", logPath)
			continue
		case "file":
			logPath := sec.Key("FILE_NAME").MustString(path.Join(LogRootPath, "gitea.log"))
			if err = os.MkdirAll(path.Dir(logPath), os.ModePerm); err != nil {
				panic(err.Error())
			}

			LogConfigs[i] = fmt.Sprintf(
				`{%s,"filename":"%s","rotate":%t,"maxsize":%d,"daily":%v,"maxdays":%d}`,
				baseConfig,
				logPath,
				sec.Key("LOG_ROTATE").MustBool(true),
				1<<uint(sec.Key("MAX_SIZE_SHIFT").MustInt(28)),
				sec.Key("DAILY_ROTATE").MustBool(true),
				sec.Key("MAX_DAYS").MustInt(7))
		case "conn":
			LogConfigs[i] = fmt.Sprintf(`{%s,"reconnectOnMsg":%v,"reconnect":%v,"net":"%s","addr":"%s"}`, baseConfig,
				sec.Key("RECONNECT_ON_MSG").MustBool(),
				sec.Key("RECONNECT").MustBool(),
				sec.Key("PROTOCOL").In("tcp", []string{"tcp", "unix", "udp"}),
				sec.Key("ADDR").MustString(":7020"))
		case "smtp":
			LogConfigs[i] = fmt.Sprintf(`{%s,"username":"%s","password":"%s","host":"%s","sendTos":["%s"],"subject":"%s"}`, baseConfig,
				sec.Key("USER").MustString("example@example.com"),
				sec.Key("PASSWD").MustString("******"),
				sec.Key("HOST").MustString("127.0.0.1:25"),
				strings.Replace(sec.Key("RECEIVERS").MustString("example@example.com"), ",", "\",\"", -1),
				sec.Key("SUBJECT").MustString("Diagnostic message from serve"))
		case "database":
			LogConfigs[i] = fmt.Sprintf(`{%s,"driver":"%s","conn":"%s"}`, baseConfig,
				sec.Key("DRIVER").String(),
				sec.Key("CONN").String())
		}

		log.NewLogger(Cfg.Section("log").Key("BUFFER_LEN").MustInt64(10000), mode, LogConfigs[i])
		log.Info("Log Mode: %s(%s)", strings.Title(mode), levelName)
	}

}

// NewXORMLogService initializes xorm logger service
func NewXORMLogService(disableConsole bool) {
	logModes := strings.Split(Cfg.Section("log").Key("MODE").MustString("console"), ",")
	var logConfigs string
	for _, mode := range logModes {
		mode = strings.TrimSpace(mode)

		if disableConsole && mode == "console" {
			continue
		}

		sec, err := Cfg.GetSection("log." + mode)
		if err != nil {
			sec, _ = Cfg.NewSection("log." + mode)
		}

		// Log level.
		levelName := getLogLevel("log."+mode, "LEVEL", LogLevel)
		level := log.FromString(levelName)

		// Generate log configuration.
		switch mode {
		case "console":
			logConfigs = fmt.Sprintf(`{"level":"%s"}`, level.String())
		case "file":
			logPath := sec.Key("FILE_NAME").MustString(path.Join(LogRootPath, "xorm.log"))
			if err = os.MkdirAll(path.Dir(logPath), os.ModePerm); err != nil {
				panic(err.Error())
			}
			logPath = path.Join(filepath.Dir(logPath), "xorm.log")

			logConfigs = fmt.Sprintf(
				`{"level":"%s","filename":"%s","rotate":%v,"maxsize":%d,"daily":%v,"maxdays":%d}`, level.String(),
				logPath,
				sec.Key("LOG_ROTATE").MustBool(true),
				1<<uint(sec.Key("MAX_SIZE_SHIFT").MustInt(28)),
				sec.Key("DAILY_ROTATE").MustBool(true),
				sec.Key("MAX_DAYS").MustInt(7))
		case "conn":
			logConfigs = fmt.Sprintf(`{"level":"%s","reconnectOnMsg":%v,"reconnect":%v,"net":"%s","addr":"%s"}`, level.String(),
				sec.Key("RECONNECT_ON_MSG").MustBool(),
				sec.Key("RECONNECT").MustBool(),
				sec.Key("PROTOCOL").In("tcp", []string{"tcp", "unix", "udp"}),
				sec.Key("ADDR").MustString(":7020"))
		case "smtp":
			logConfigs = fmt.Sprintf(`{"level":"%s","username":"%s","password":"%s","host":"%s","sendTos":"%s","subject":"%s"}`, level.String(),
				sec.Key("USER").MustString("example@example.com"),
				sec.Key("PASSWD").MustString("******"),
				sec.Key("HOST").MustString("127.0.0.1:25"),
				sec.Key("RECEIVERS").MustString("[]"),
				sec.Key("SUBJECT").MustString("Diagnostic message from serve"))
		case "database":
			logConfigs = fmt.Sprintf(`{"level":"%s","driver":"%s","conn":"%s"}`, level.String(),
				sec.Key("DRIVER").String(),
				sec.Key("CONN").String())
		}

		log.NewXORMLogger(Cfg.Section("log").Key("BUFFER_LEN").MustInt64(10000), mode, logConfigs)
		if !disableConsole {
			log.Info("XORM Log Mode: %s(%s)", strings.Title(mode), levelName)
		}

		var lvl core.LogLevel
		switch levelName {
		case "Trace", "Debug":
			lvl = core.LOG_DEBUG
		case "Info":
			lvl = core.LOG_INFO
		case "Warn":
			lvl = core.LOG_WARNING
		case "Error", "Critical":
			lvl = core.LOG_ERR
		}
		log.XORMLogger.SetLevel(lvl)
	}

	if len(logConfigs) == 0 {
		log.DiscardXORMLogger()
	}
}
