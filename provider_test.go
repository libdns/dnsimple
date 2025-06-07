package dnsimple_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/libdns/dnsimple"
	"github.com/libdns/libdns"
)

var (
	apiAccessToken = os.Getenv("TEST_API_ACCESS_TOKEN")
	zone           = os.Getenv("TEST_ZONE")
	apiUrl         = "https://api.sandbox.dnsimple.com"
	ttl            = time.Duration(1 * time.Hour)
)

type testRecordsCleanup = func()

func TestMain(m *testing.M) {
	if len(apiAccessToken) == 0 || len(zone) == 0 {
		panic("API Access Token, Zone, and Account ID must be set using environment variables")
	}

	os.Exit(m.Run())
}

func setupTestRecords(t *testing.T, ctx context.Context, p *dnsimple.Provider) ([]libdns.Record, testRecordsCleanup) {
	testRecords := []libdns.Record{
		libdns.RR{
			Type: "TXT",
			Name: "test1",
			Data: "test1",
			TTL:  ttl,
		}, libdns.RR{
			Type: "TXT",
			Name: "test2",
			Data: "test2",
			TTL:  ttl,
		}, libdns.RR{
			Type: "TXT",
			Name: "test3",
			Data: "test3",
			TTL:  ttl,
		},
	}
	records, err := p.AppendRecords(context.Background(), zone, testRecords)
	if err != nil {
		t.Fatal(err)
		return nil, func() {}
	}

	return records, func() {
		cleanupRecords(t, ctx, p, records)
	}
}

func cleanupRecords(t *testing.T, ctx context.Context, p *dnsimple.Provider, r []libdns.Record) {
	_, err := p.DeleteRecords(ctx, zone, r)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
}

func Test_AppendRecords(t *testing.T) {
	p := &dnsimple.Provider{
		APIAccessToken: apiAccessToken,
		APIURL:         apiUrl,
	}
	ctx := context.Background()

	testCases := []struct {
		records  []libdns.Record
		expected []libdns.Record
	}{
		{
			records: []libdns.Record{
				libdns.RR{Type: "TXT", Name: "test_1", Data: "test_1", TTL: ttl},
				libdns.RR{Type: "TXT", Name: "test_2", Data: "test_2", TTL: ttl},
				libdns.RR{Type: "TXT", Name: "test_3", Data: "test_3", TTL: ttl},
			},
			expected: []libdns.Record{
				libdns.RR{Type: "TXT", Name: "test_1", Data: "test_1", TTL: ttl},
				libdns.RR{Type: "TXT", Name: "test_2", Data: "test_2", TTL: ttl},
				libdns.RR{Type: "TXT", Name: "test_3", Data: "test_3", TTL: ttl},
			},
		},
		{
			records: []libdns.Record{
				libdns.RR{Type: "TXT", Name: "123.test", Data: "123", TTL: ttl},
			},
			expected: []libdns.Record{
				libdns.RR{Type: "TXT", Name: "123.test", Data: "123", TTL: ttl},
			},
		},
		{
			records: []libdns.Record{
				libdns.RR{Type: "TXT", Name: "123.test", Data: "test", TTL: ttl},
			},
			expected: []libdns.Record{
				libdns.RR{Type: "TXT", Name: "123.test", Data: "test", TTL: ttl},
			},
		},
		{
			records: []libdns.Record{
				libdns.RR{Type: "TXT", Name: "abc.test", Data: "test", TTL: ttl},
			},
			expected: []libdns.Record{
				libdns.RR{Type: "TXT", Name: "abc.test", Data: "test", TTL: ttl},
			},
		},
	}

	for _, c := range testCases {
		func() {
			result, err := p.AppendRecords(ctx, zone+".", c.records)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanupRecords(t, ctx, p, result)

			if len(result) != len(c.records) {
				t.Fatalf("len(resilt) != len(c.records) => %d != %d", len(c.records), len(result))
			}

			for k, r := range result {
				if r.RR().Type != c.expected[k].RR().Type {
					t.Fatalf("r.Type != c.exptected[%d].Type => %s != %s", k, r.RR().Type, c.expected[k].RR().Type)
				}
				if r.RR().Name != c.expected[k].RR().Name {
					t.Fatalf("r.Name != c.exptected[%d].Name => %s != %s", k, r.RR().Name, c.expected[k].RR().Name)
				}
				if r.RR().Data != c.expected[k].RR().Data {
					t.Fatalf("r.Value != c.exptected[%d].Value => %s != %s", k, r.RR().Data, c.expected[k].RR().Data)
				}
				if r.RR().TTL != c.expected[k].RR().TTL {
					t.Fatalf("r.TTL != c.exptected[%d].TTL => %s != %s", k, r.RR().TTL, c.expected[k].RR().TTL)
				}
			}
		}()
	}
}

func Test_DeleteRecords(t *testing.T) {
	p := &dnsimple.Provider{
		APIAccessToken: apiAccessToken,
		APIURL:         apiUrl,
	}
	ctx := context.Background()

	testRecords, cleanupFunc := setupTestRecords(t, ctx, p)
	defer cleanupFunc()

	records, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	if len(records) < len(testRecords) {
		t.Fatalf("len(records) < len(testRecords) => %d < %d", len(records), len(testRecords))
	}

	for _, testRecord := range testRecords {
		var foundRecord *libdns.Record
		for _, record := range records {
			if testRecord.RR().Name == record.RR().Name && testRecord.RR().Type == record.RR().Type {
				foundRecord = &testRecord
			}
		}

		if foundRecord == nil {
			t.Fatalf("Record not found => %s", testRecord.RR().Name)
		}
	}
}

func Test_GetRecords(t *testing.T) {
	p := &dnsimple.Provider{
		APIAccessToken: apiAccessToken,
		APIURL:         apiUrl,
	}
	ctx := context.Background()

	testRecords, cleanupFunc := setupTestRecords(t, ctx, p)
	defer cleanupFunc()

	records, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	if len(records) < len(testRecords) {
		t.Fatalf("len(records) < len(testRecords) => %d < %d", len(records), len(testRecords))
	}

	for _, testRecord := range testRecords {
		var foundRecord *libdns.Record
		for _, record := range records {
			if testRecord.RR().Name == record.RR().Name && testRecord.RR().Type == record.RR().Type {
				foundRecord = &testRecord
			}
		}

		if foundRecord == nil {
			t.Fatalf("Record not found => %s", testRecord.RR().Name)
		}
	}
}

func Test_SetRecords(t *testing.T) {
	p := &dnsimple.Provider{
		APIAccessToken: apiAccessToken,
		APIURL:         apiUrl,
	}
	ctx := context.Background()

	existingRecords, _ := setupTestRecords(t, ctx, p)

	newTestRecords := []libdns.Record{
		libdns.RR{
			Type: "A",
			Name: "new_test1",
			Data: "192.168.1.1",
			TTL:  ttl,
		},
		libdns.RR{
			Type: "A",
			Name: "new_test2",
			Data: "192.168.1.2",
			TTL:  ttl,
		},
	}

	allRecords := append(existingRecords, newTestRecords...)
	for i, record := range allRecords {
		if record.RR().Type == "TXT" {
			switch record.RR().Name {
			case "test1":
				allRecords[i] = libdns.RR{Type: "TXT", Name: "test1", Data: "updated_test1", TTL: ttl}
			case "test2":
				allRecords[i] = libdns.RR{Type: "TXT", Name: "test2", Data: "updated_test2", TTL: ttl}
			case "test3":
				allRecords[i] = libdns.RR{Type: "TXT", Name: "test3", Data: "updated_test3", TTL: ttl}
			}
		}
	}

	records, err := p.SetRecords(ctx, zone, allRecords)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupRecords(t, ctx, p, records)

	if len(records) != len(allRecords) {
		t.Fatalf("len(records) != len(allRecords) => %d != %d", len(records), len(allRecords))
	}

	expectedUpdates := map[string]string{
		"test1": "updated_test1",
		"test2": "updated_test2",
		"test3": "updated_test3",
	}

	found := make(map[string]bool)
	for _, r := range records {
		for name, expectedData := range expectedUpdates {
			if r.RR().Data == expectedData {
				found[name] = true
			}
		}
	}

	for name := range expectedUpdates {
		if !found[name] {
			t.Fatalf("Did not update value on existing record: %s", name)
		}
	}

	expectedARecords := map[string]string{
		"new_test1": "192.168.1.1",
		"new_test2": "192.168.1.2",
	}

	foundARecords := make(map[string]bool)
	for _, r := range records {
		if r.RR().Type == "A" {
			for name, expectedData := range expectedARecords {
				if r.RR().Name == name && r.RR().Data == expectedData {
					foundARecords[name] = true
				}
			}
		}
	}

	for name := range expectedARecords {
		if !foundARecords[name] {
			t.Fatalf("Did not create A record: %s", name)
		}
	}
}
