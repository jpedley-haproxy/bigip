// Copyright © 2026 Sébastien Gross <seb•ɑƬ•chezwam•ɖɵʈ•org>
//
// Created: 2021-12-31
// Last changed: 2024-10-29 11:49:09
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see
// <http://www.gnu.org/licenses/>.

package haproxy

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"bigip/f5"

	"github.com/Masterminds/sprig"
)

// f5field extracts a scalar field value from raw F5 config content.
// Handles both quoted ("value") and unquoted values.
func f5field(content, field string) string {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(field) + `\s+("(?:[^"\\]|\\.)*"|[^\s{}\n]+)`)
	m := re.FindStringSubmatch(content)
	if m == nil {
		return ""
	}
	v := m[1]
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	return v
}

// f5options extracts the token list from an F5 "options { ... }" block.
func f5options(content string) []string {
	re := regexp.MustCompile(`(?s)\boptions\s*\{([^}]*)\}`)
	m := re.FindStringSubmatch(content)
	if m == nil {
		return nil
	}
	return strings.Fields(strings.TrimSpace(m[1]))
}

// f5block extracts the raw content of a named single-level F5 block.
func f5block(content, blockName string) string {
	re := regexp.MustCompile(`(?s)\b` + regexp.QuoteMeta(blockName) + `\s*\{([^}]*)\}`)
	m := re.FindStringSubmatch(content)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// f5tlsMinVer returns the HAProxy ssl-min-ver value implied by F5 no-tlsv* options.
// Returns an empty string when no minimum restriction is needed (TLSv1.0 is the default).
func f5tlsMinVer(options []string) string {
	disabled := map[string]bool{}
	for _, opt := range options {
		switch opt {
		case "no-tlsv1":
			disabled["1.0"] = true
		case "no-tlsv1.1":
			disabled["1.1"] = true
		case "no-tlsv1.2":
			disabled["1.2"] = true
		case "no-tlsv1.3":
			disabled["1.3"] = true
		}
	}
	for _, ver := range []string{"1.0", "1.1", "1.2", "1.3"} {
		if !disabled[ver] {
			if ver == "1.0" {
				return ""
			}
			return "TLSv" + ver
		}
	}
	return ""
}

// f5tlsMaxVer returns the HAProxy ssl-max-ver value implied by F5 no-tlsv* options.
// Returns an empty string when no maximum restriction is needed (TLSv1.3 is the default).
func f5tlsMaxVer(options []string) string {
	disabled := map[string]bool{}
	for _, opt := range options {
		switch opt {
		case "no-tlsv1":
			disabled["1.0"] = true
		case "no-tlsv1.1":
			disabled["1.1"] = true
		case "no-tlsv1.2":
			disabled["1.2"] = true
		case "no-tlsv1.3":
			disabled["1.3"] = true
		}
	}
	for _, ver := range []string{"1.3", "1.2", "1.1", "1.0"} {
		if !disabled[ver] {
			if ver == "1.3" {
				return ""
			}
			return "TLSv" + ver
		}
	}
	return ""
}

// f5cipherGroupStr resolves an F5 cipher group name to a colon-separated
// cipher string by following the group → rule → cipher chain.
func f5cipherGroupStr(groupName string, fullConfig f5.F5Config) string {
	if groupName == "" || groupName == "none" {
		return ""
	}
	groupObj := fullConfig.LtmCipherGroup[groupName]
	if groupObj == nil {
		return ""
	}
	allowContent := f5block(groupObj.Original(), "allow")
	if allowContent == "" {
		return ""
	}
	// Each rule reference in the allow block looks like: /Common/name { }
	nameRe := regexp.MustCompile(`(/[^\s{]+)`)
	var ciphers []string
	for _, m := range nameRe.FindAllStringSubmatch(allowContent, -1) {
		ruleObj := fullConfig.LtmCipherRule[m[1]]
		if ruleObj == nil {
			continue
		}
		if c := f5field(ruleObj.Original(), "cipher"); c != "" {
			ciphers = append(ciphers, c)
		}
	}
	return strings.Join(ciphers, ":")
}

// f5clientSslBindOpts builds the HAProxy bind-line SSL option string from a raw
// client-ssl profile block. Returns a string beginning with " ssl " ready to
// be appended to the bind address/port.
func f5clientSslBindOpts(content string, fullConfig f5.F5Config) string {
	var parts []string

	// Extract the first cert from a cert-key-chain block.
	certRe := regexp.MustCompile(`(?m)^\s+cert\s+(/\S+)`)
	if m := certRe.FindStringSubmatch(content); m != nil && m[1] != "none" {
		name := m[1]
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		parts = append(parts, "crt /var/lib/dataplaneapi/storage/certs/"+name+".pem")
	} else {
		parts = append(parts, "crt /var/lib/dataplaneapi/storage/certs/PLACEHOLDER.pem")
	}

	opts := f5options(content)
	minVer := f5tlsMinVer(opts)
	maxVer := f5tlsMaxVer(opts)
	if minVer != "" || maxVer != "" {
		var verParts []string
		if minVer != "" {
			verParts = append(verParts, "ssl-min-ver "+minVer)
		}
		if maxVer != "" {
			verParts = append(verParts, "ssl-max-ver "+maxVer)
		}
		parts = append(parts, strings.Join(verParts, " "))
	}

	ciphers := f5field(content, "ciphers")
	if ciphers != "" && ciphers != "none" && ciphers != "DEFAULT" {
		parts = append(parts, "ciphers "+ciphers)
	} else if cipherGroup := f5field(content, "cipher-group"); cipherGroup != "" {
		if resolved := f5cipherGroupStr(cipherGroup, fullConfig); resolved != "" {
			parts = append(parts, "ciphers "+resolved)
		}
	}

	return " ssl " + strings.Join(parts, " ")
}

// f5httpSend converts an F5 monitor send string to HAProxy http-check send arguments.
// F5 uses literal \r\n / \n\r sequences as line terminators inside quoted strings.
func f5httpSend(send string) string {
	firstLine := send
	for _, sep := range []string{`\n\r`, `\r\n`, `\r`, `\n`} {
		if idx := strings.Index(send, sep); idx >= 0 {
			firstLine = send[:idx]
			break
		}
	}
	firstLine = strings.TrimSpace(firstLine)
	parts := strings.Fields(firstLine)
	if len(parts) == 0 {
		return ""
	}
	result := "meth " + parts[0]
	if len(parts) >= 2 {
		result += " uri " + parts[1]
	}
	ver := ""
	if len(parts) >= 3 {
		ver = parts[2]
		result += " ver " + ver
	}
	if ver == "HTTP/1.1" {
		result += " hdr Host PLACEHOLDER"
	}
	return result
}

func add(a, b int) int {
	return a + b
}
func sub(a, b int) int {
	return a - b
}

func comment(str string, indent int, comment string) string {
	return spacedComment(str, 1, indent, comment)
}

func spacedComment(str string, space, indent int, comment string) string {
	idstr := strings.Repeat(" ", indent)
	spstr := strings.Repeat(" ", space)
	lines := strings.Split(str, "\n")
	for i, line := range lines {
		lines[i] = idstr + comment + spstr + line
	}
	return strings.Join(lines, "\n")
}

func indent(str string, indent int) string {
	idstr := strings.Repeat(" ", indent)
	lines := strings.Split(str, "\n")
	for i, line := range lines {
		lines[i] = idstr + line
	}
	return strings.Join(lines, "\n")
}

func split(str, sep string) []string {
	strs := strings.Split(str, sep)
	return strs
}

func stripport(str string) string {
	strs := strings.Split(str, ":")
	return strs[0]
}

func ipport(str string) string {
	strs := strings.Split(str, "/")
	ipport := strings.Split(strs[len(strs)-1], ":")
	ipport[0] = strings.Split(ipport[0], "%")[0]

	return strings.Join(ipport, ":")
}

func normalize(str string) string {
	if len(str) == 0 {
		return str
	}
	if str[0] == '/' {
		str = str[1:]
	}
	str = strings.Replace(str, "/", "::", -1)
	str = strings.Replace(str, " ", "_", -1)
	return str

}

func loadTemplates(config *Config) (tmpls *template.Template, err error) {
	tmpls = template.New("")
	funcs := template.FuncMap{
		"add":       add,
		"sub":       sub,
		"comment":   comment,
		"scomment":  spacedComment,
		"indent":    indent,
		"stripport": stripport,
		"split":     split,
		"ipport":    ipport,
		"normalize":   normalize,
		"f5cipherGroupStr":    f5cipherGroupStr,
		"f5clientSslBindOpts": f5clientSslBindOpts,
		"f5field":             f5field,
		"f5options":   f5options,
		"f5block":     f5block,
		"f5tlsMinVer": f5tlsMinVer,
		"f5tlsMaxVer": f5tlsMaxVer,
		"f5httpSend":  f5httpSend,
		// https://forum.golangbridge.org/t/template-check-if-block-is-defined/6928/2
		"hasTemplate": func(name string) bool {
			return tmpls.Lookup(name) != nil
		},
		"templateIfExists": func(name string, pipeline interface{}) (string, error) {
			t := tmpls.Lookup(name)
			if t == nil {
				return "", nil
			}

			buf := &bytes.Buffer{}
			err := t.Execute(buf, pipeline)
			if err != nil {
				return "", err
			}

			return buf.String(), nil
		},
		"templateIndent": func(level int64, name string, pipeline interface{}) (string, error) {
			if !config.ExpandTemplates && level != 0 {
				return fmt.Sprintf(`{{   templateIndent %d "%s" "%s" }}`, level, name, pipeline), nil
			} // else {
			// 	fmt.Printf("expending %s: %t && %t, %i\n", name, !config.ExpandTemplates, level != 0, level)
			// }

			lvl := int(level)
			if lvl < 0 {
				lvl = 0
			}

			// Disabled template
			switch p := pipeline.(type) {
			case string:
				if strings.HasPrefix(p, "disabled:") {
					idstr := strings.Repeat(" ", lvl)
					return fmt.Sprintf("%s# %s | %s", idstr, name, p), nil
				}
			}

			t := tmpls.Lookup(name)
			if t == nil {
				config.Log.Error("Template %s not found", name)
				return fmt.Sprintf("%s### Template %s not found", strings.Repeat(" ", lvl), name), err
			}

			buf := &bytes.Buffer{}
			err := t.Execute(buf, pipeline)
			if err != nil {
				return "", err
			}

			idstr := strings.Repeat(" ", lvl)
			lines := strings.Split(buf.String(), "\n")
			for i, line := range lines {
				lines[i] = idstr + line
			}
			return strings.Join(lines, "\n"), nil
		},
	}
	tmpls = tmpls.Funcs(sprig.TxtFuncMap())
	tmpls = tmpls.Funcs(funcs)
	tmpls, err = tmpls.ParseFS(tpl, "templates/*.tpl.cfg")
	if err != nil {
		return
	}

	for _, td := range config.TemplateDir {
		err = addExtraTemplates(tmpls, td)
		if err != nil {
			return
		}
	}
	return
}
