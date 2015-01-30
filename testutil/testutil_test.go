package testutil

import "testing"

func cycleSingleServer(t *testing.T) {
	_, teardown := SingleServer(t)
	teardown()
}

func TestSingleServer1(t *testing.T) { cycleSingleServer(t) }
func TestSingleServer2(t *testing.T) { cycleSingleServer(t) }
func TestSingleServer3(t *testing.T) { cycleSingleServer(t) }
