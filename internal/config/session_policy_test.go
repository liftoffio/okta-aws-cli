/*
 * Copyright (c) 2022-Present, Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetAWSSessionPolicyFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	const policy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

	c := &Config{}
	require.NoError(t, c.SetAWSSessionPolicyFile(""))
	require.Equal(t, "", c.AWSSessionPolicy())

	require.NoError(t, c.SetAWSSessionPolicyFile(write("policy.json", policy)))
	require.Equal(t, policy, c.AWSSessionPolicy())

	// Each failure must also clear a policy set earlier, so a bad file never
	// leaves a stale policy in place.
	for _, path := range []string{
		filepath.Join(dir, "missing.json"),
		write("empty.json", ""),
		write("bad.json", `{"Version":`),
	} {
		require.NoError(t, c.SetAWSSessionPolicyFile(write("policy.json", policy)))
		require.Error(t, c.SetAWSSessionPolicyFile(path), path)
		require.Equal(t, "", c.AWSSessionPolicy(), path)
	}
}
