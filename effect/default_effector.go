// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package effect

import "errors"

// DefaultEffector is default effector for Casbin.
type DefaultEffector struct {
}

// NewDefaultEffector is the constructor for DefaultEffector.
func NewDefaultEffector() *DefaultEffector {
	e := DefaultEffector{}
	return &e
}

// MergeEffects merges all matching results collected by the enforcer into a single decision.
func (e *DefaultEffector) MergeEffects(expr string, effects []HierarchyEffect, results []float64) (bool, error) {
	result := false
	if expr == "some(where (p_eft == allow))" {
		result = false
		for _, eft := range effects {
			if eft.Effect == Allow {
				result = true
				break
			}
		}
	} else if expr == "!some(where (p_eft == deny))" {
		result = true
		for _, eft := range effects {
			if eft.Effect == Deny {
				result = false
				break
			}
		}
	} else if expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))" {
		result = false
		for _, eft := range effects {
			if eft.Effect == Allow {
				result = true
			} else if eft.Effect == Deny {
				result = false
				break
			}
		}
	} else if expr == "priority(p_eft) || deny" {
		result = false
		for _, eft := range effects {
			if eft.Effect != Indeterminate {
				if eft.Effect == Allow {
					result = true
				} else {
					result = false
				}
				break
			}
		}
	} else if expr == "hierarchy(p_eft)" {
		result = false
		level := 10
		for _, eft := range effects {
			if eft.Effect != Indeterminate {
				if eft.Level > level {
					if eft.Effect == Allow {
						result = true
						level = eft.Level
					} else {
						result = false
						level = eft.Level
					}
				}
			}
		}
	} else {
		return false, errors.New("unsupported effect")
	}

	return result, nil
}
