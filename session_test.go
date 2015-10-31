/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package session

import (
	"testing"

	"github.com/mailgun/lemma/secret"

	. "gopkg.in/check.v1" // note that we don't vendor libraries dependencies, only end daemons deps are vendored
)

func TestSession(t *testing.T) { TestingT(t) }

type SessionSuite struct {
	srv secret.SecretService
}

var _ = Suite(&SessionSuite{})

func (s *SessionSuite) SetUpSuite(c *C) {
	key, err := secret.NewKey()
	c.Assert(err, IsNil)
	srv, err := secret.New(&secret.Config{KeyBytes: key})
	c.Assert(err, IsNil)
	s.srv = srv
}

func (s *SessionSuite) TestDecodeOK(c *C) {
	p, err := NewID(s.srv)
	c.Assert(err, IsNil)

	pid, err := DecodeSID(p.SID, s.srv)
	c.Assert(err, IsNil)
	c.Assert(string(pid), Equals, string(p.PID))
}

func (s *SessionSuite) TestDecodeHardcodedOK(c *C) {
	p, err := EncodeID("my-id", s.srv)
	c.Assert(err, IsNil)

	pid, err := DecodeSID(p.SID, s.srv)
	c.Assert(err, IsNil)
	c.Assert(string(pid), Equals, string("my-id"))
}

func (s *SessionSuite) TestTamperNotOK(c *C) {
	p, err := NewID(s.srv)
	c.Assert(err, IsNil)

	tc := []SecureID{
		p.SID[:len(p.SID)-1],
		"_" + p.SID,
		"",
		"blabla",
		p.SID + "a",
		p.SID[0:len(p.SID)-1] + "_",
	}

	for _, t := range tc {
		_, err = DecodeSID(t, s.srv)
		c.Assert(err, FitsTypeOf, &MalformedSessionError{})
	}
}
