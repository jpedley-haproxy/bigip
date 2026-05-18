// Copyright © 2026 Sébastien Gross <seb•ɑƬ•chezwam•ɖɵʈ•org>
//
// Created: 2024-05-18
// Last changed: 2024-05-18
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

package f5

import (
	"fmt"
	"strings"
)

// LtmCipherGroup represents an F5 "ltm cipher group" block.
// The allow list references LtmCipherRule names whose cipher strings are used.
type LtmCipherGroup struct {
	OriginalConfig ParsedConfig
	Name           string
}

func (o *LtmCipherGroup) Original() string { return o.OriginalConfig.Content }
func (o *LtmCipherGroup) GetName() string  { return o.Name }

func newLtmCipherGroup(data ParsedConfig) (*LtmCipherGroup, error) {
	firstLine := strings.SplitN(data.Content, "\n", 2)[0]
	parts := strings.Fields(firstLine)
	// "ltm cipher group /Common/name {"
	if len(parts) < 4 {
		return nil, fmt.Errorf("cannot parse cipher group: %s", firstLine)
	}
	return &LtmCipherGroup{OriginalConfig: data, Name: parts[3]}, nil
}

// LtmCipherRule represents an F5 "ltm cipher rule" block.
// The cipher field holds the colon-separated cipher string.
type LtmCipherRule struct {
	OriginalConfig ParsedConfig
	Name           string
}

func (o *LtmCipherRule) Original() string { return o.OriginalConfig.Content }
func (o *LtmCipherRule) GetName() string  { return o.Name }

func newLtmCipherRule(data ParsedConfig) (*LtmCipherRule, error) {
	firstLine := strings.SplitN(data.Content, "\n", 2)[0]
	parts := strings.Fields(firstLine)
	// "ltm cipher rule /Common/name {"
	if len(parts) < 4 {
		return nil, fmt.Errorf("cannot parse cipher rule: %s", firstLine)
	}
	return &LtmCipherRule{OriginalConfig: data, Name: parts[3]}, nil
}
