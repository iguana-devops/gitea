// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package i18n

import (
	"strings"
	"text/template"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/translation/i18n/plurals"
)

type locale struct {
	store       *localeStore
	langName    string
	idxToMsgMap map[int]string // the map idx is generated by store's trKeyToIdxMap

	tmpl *template.Template
}

func newLocale(store *localeStore, langName string) *locale {
	return &locale{store: store, langName: langName, idxToMsgMap: make(map[int]string), tmpl: &template.Template{}}
}

// Tr translates content to locale language. fall back to default language.
func (l *locale) Tr(trKey string, trArgs ...interface{}) string {
	format := trKey

	idx, ok := l.store.trKeyToIdxMap[trKey]
	if ok {
		if msg, ok := l.idxToMsgMap[idx]; ok {
			format = msg // use the found translation
		} else if def, ok := l.store.localeMap[l.store.defaultLang]; ok {
			// try to use default locale's translation
			if msg, ok := def.idxToMsgMap[idx]; ok {
				format = msg
			}
		}
	}

	msg, err := Format(l, format, trArgs...)
	if err != nil {
		log.Error("Error whilst formatting %q in %s: %v", trKey, l.langName, err)
	}
	return msg
}

// Has returns whether a key is present in this locale or not
func (l *locale) Has(trKey string) bool {
	idx, ok := l.store.trKeyToIdxMap[trKey]
	if !ok {
		return false
	}
	_, ok = l.idxToMsgMap[idx]
	return ok
}

func (l *locale) TrOrdinal(cnt interface{}, trKey string, args ...interface{}) string {
	return l.trPlurals(cnt, plurals.DefaultRules.Ordinal(l.langName), trKey, args...)
}

func (l *locale) TrPlural(cnt interface{}, trKey string, args ...interface{}) string {
	return l.trPlurals(cnt, plurals.DefaultRules.Rule(l.langName), trKey, args...)
}

func (l *locale) TrPlurals(cnt interface{}, ruleType, trKey string, args ...interface{}) string {
	return l.trPlurals(cnt, plurals.DefaultRules.RuleByType(plurals.RuleType(ruleType), l.langName), trKey, args...)
}

func (l *locale) trPlurals(cnt interface{}, rule *plurals.Rule, trKey string, args ...interface{}) string {
	if rule == nil {
		// if we fail to parse fall back to the standard
		return l.Tr(trKey, args...)
	}

	operands, err := plurals.NewOperands(cnt)
	if err != nil {
		// if we fail to parse fall back to the standard
		return l.Tr(trKey, args...)
	}

	textIdx, ok := l.store.trKeyToIdxMap[trKey]
	if !ok {
		// if we fail to parse fall back to the standard
		return l.Tr(trKey, args...)
	}
	msg, found := l.idxToMsgMap[textIdx]
	if !found {
		if def, ok := l.store.localeMap[l.store.defaultLang]; ok {
			// try to use default locale's translation
			msg, found = def.idxToMsgMap[textIdx]
		}
	}
	if !found {
		// if we fail to parse fall back to the standard
		return l.Tr(trKey, args...)
	}

	form := rule.PluralFormFunc(operands)

	tmpl := l.tmpl.Lookup(trKey)
	if tmpl == nil {
		tmpl = l.tmpl.New(trKey)
		_, err := tmpl.Parse(msg)
		if err != nil {
			log.Error("Misformatted key %s in %s: %v", trKey, l.langName, err)
			_, _ = tmpl.Parse(strings.ReplaceAll(trKey, "{{", "{{printf \"{{\"}}"))
		}
	}

	sb := &strings.Builder{}
	err = tmpl.Execute(sb, form)
	if err != nil {
		return l.Tr(trKey, args...) // fall back to the standard
	}

	return sb.String()
}
