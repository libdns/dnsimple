package dnsimple_test

import (
	"context"
	"fmt"
	"os"
	"sync"
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
		{
			Type:  "TXT",
			Name:  "test1",
			Value: "test1",
			TTL:   ttl,
		}, {
			Type:  "TXT",
			Name:  "test2",
			Value: "test2",
			TTL:   ttl,
		}, {
			Type:  "TXT",
			Name:  "test3",
			Value: "test3",
			TTL:   ttl,
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
				{Type: "TXT", Name: "test_1", Value: "test_1", TTL: ttl},
				{Type: "TXT", Name: "test_2", Value: "test_2", TTL: ttl},
				{Type: "TXT", Name: "test_3", Value: "test_3", TTL: ttl},
			},
			expected: []libdns.Record{
				{Type: "TXT", Name: "test_1", Value: "test_1", TTL: ttl},
				{Type: "TXT", Name: "test_2", Value: "test_2", TTL: ttl},
				{Type: "TXT", Name: "test_3", Value: "test_3", TTL: ttl},
			},
		},
		{
			records: []libdns.Record{
				{Type: "TXT", Name: "123.test", Value: "123", TTL: ttl},
			},
			expected: []libdns.Record{
				{Type: "TXT", Name: "123.test", Value: "123", TTL: ttl},
			},
		},
		{
			records: []libdns.Record{
				{Type: "TXT", Name: "123.test", Value: "test", TTL: ttl},
			},
			expected: []libdns.Record{
				{Type: "TXT", Name: "123.test", Value: "test", TTL: ttl},
			},
		},
		{
			records: []libdns.Record{
				{Type: "TXT", Name: "abc.test", Value: "test", TTL: ttl},
			},
			expected: []libdns.Record{
				{Type: "TXT", Name: "abc.test", Value: "test", TTL: ttl},
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
				if len(result[k].ID) == 0 {
					t.Fatalf("len(result[%d].ID) == 0", k)
				}
				if r.Type != c.expected[k].Type {
					t.Fatalf("r.Type != c.exptected[%d].Type => %s != %s", k, r.Type, c.expected[k].Type)
				}
				if r.Name != c.expected[k].Name {
					t.Fatalf("r.Name != c.exptected[%d].Name => %s != %s", k, r.Name, c.expected[k].Name)
				}
				if r.Value != c.expected[k].Value {
					t.Fatalf("r.Value != c.exptected[%d].Value => %s != %s", k, r.Value, c.expected[k].Value)
				}
				if r.TTL != c.expected[k].TTL {
					t.Fatalf("r.TTL != c.exptected[%d].TTL => %s != %s", k, r.TTL, c.expected[k].TTL)
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
			if testRecord.ID == record.ID {
				foundRecord = &testRecord
			}
		}

		if foundRecord == nil {
			t.Fatalf("Record not found => %s", testRecord.ID)
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
			if testRecord.ID == record.ID {
				foundRecord = &testRecord
			}
		}

		if foundRecord == nil {
			t.Fatalf("Record not found => %s", testRecord.ID)
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
		{
			Type:  "TXT",
			Name:  "new_test1",
			Value: "new_test1",
			TTL:   ttl,
		},
		{
			Type:  "TXT",
			Name:  "new_test2",
			Value: "new_test2",
			TTL:   ttl,
		},
	}

	allRecords := append(existingRecords, newTestRecords...)
	allRecords[0].Value = "new_value"

	records, err := p.SetRecords(ctx, zone, allRecords)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupRecords(t, ctx, p, records)

	if len(records) != len(allRecords) {
		t.Fatalf("len(records) != len(allRecords) => %d != %d", len(records), len(allRecords))
	}

	updated := false
	for _, r := range records {
		if r.Value == "new_value" {
			updated = true
		}
	}
	if !updated {
		t.Fatalf("Did not update value on existing record")
	}
}

func Test_ConcurrentOperations(t *testing.T) {
	p := &dnsimple.Provider{
		APIAccessToken: apiAccessToken,
		APIURL:         apiUrl,
	}
	ctx := context.Background()

	// Phase 1: Test concurrent AppendRecords operations
	var wg sync.WaitGroup
	const numGoroutines = 5
	results := make([][]libdns.Record, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			record := libdns.RR{
				Type: "TXT",
				Name: fmt.Sprintf("concurrent-%d", id),
				Data: fmt.Sprintf("test-data-%d", id),
				TTL:  ttl,
			}
			result, err := p.AppendRecords(ctx, zone, []libdns.Record{record})
			results[id] = result
			errors[id] = err
		}(i)
	}

	wg.Wait()

	// Verify all append operations succeeded
	var allCreatedRecords []libdns.Record
	for i := range numGoroutines {
		if errors[i] != nil {
			t.Fatalf("Append goroutine %d failed: %v", i, errors[i])
		}
		if len(results[i]) != 1 {
			t.Fatalf("Append goroutine %d: expected 1 record, got %d", i, len(results[i]))
		}
		allCreatedRecords = append(allCreatedRecords, results[i]...)
	}

	// Phase 2: Test concurrent SetRecords operations (updating existing records)
	var setWg sync.WaitGroup
	setResults := make([][]libdns.Record, numGoroutines)
	setErrors := make([]error, numGoroutines)

	for i := range numGoroutines {
		setWg.Add(1)
		go func(id int) {
			defer setWg.Done()
			// Update the record we just created
			updatedRecord := libdns.RR{
				Type: "TXT",
				Name: fmt.Sprintf("concurrent-%d", id),
				Data: fmt.Sprintf("updated-data-%d", id),
				TTL:  ttl,
			}
			result, err := p.SetRecords(ctx, zone, []libdns.Record{updatedRecord})
			setResults[id] = result
			setErrors[id] = err
		}(i)
	}

	setWg.Wait()

	// Verify all set operations succeeded
	var allUpdatedRecords []libdns.Record
	for i := range numGoroutines {
		if setErrors[i] != nil {
			t.Fatalf("Set goroutine %d failed: %v", i, setErrors[i])
		}
		if len(setResults[i]) != 1 {
			t.Fatalf("Set goroutine %d: expected 1 record, got %d", i, len(setResults[i]))
		}
		allUpdatedRecords = append(allUpdatedRecords, setResults[i]...)
	}

	// Verify records were updated correctly
	for i, record := range allUpdatedRecords {
		expectedName := fmt.Sprintf("concurrent-%d", i)
		expectedData := fmt.Sprintf("updated-data-%d", i)

		if record.RR().Name != expectedName {
			t.Fatalf("Updated record %d: expected name %s, got %s", i, expectedName, record.RR().Name)
		}
		if record.RR().Data != expectedData {
			t.Fatalf("Updated record %d: expected data %s, got %s", i, expectedData, record.RR().Data)
		}
	}

	// Phase 3: Test concurrent GetRecords operations
	var getWg sync.WaitGroup
	getResults := make([][]libdns.Record, 3)
	getErrors := make([]error, 3)

	for i := range 3 {
		getWg.Add(1)
		go func(id int) {
			defer getWg.Done()
			records, err := p.GetRecords(ctx, zone)
			getResults[id] = records
			getErrors[id] = err
		}(i)
	}

	getWg.Wait()

	// Verify all GetRecords operations succeeded
	for i := range 3 {
		if getErrors[i] != nil {
			t.Fatalf("Concurrent GetRecords %d failed: %v", i, getErrors[i])
		}
		// All should return at least the records we created/updated
		if len(getResults[i]) < numGoroutines {
			t.Fatalf("Concurrent GetRecords %d: expected at least %d records, got %d", i, numGoroutines, len(getResults[i]))
		}
	}

	// Phase 4: Test concurrent DeleteRecords operations
	var deleteWg sync.WaitGroup
	deleteResults := make([][]libdns.Record, numGoroutines)
	deleteErrors := make([]error, numGoroutines)

	for i := range numGoroutines {
		deleteWg.Add(1)
		go func(id int) {
			defer deleteWg.Done()
			// Delete the record we created/updated
			recordToDelete := allUpdatedRecords[id]
			result, err := p.DeleteRecords(ctx, zone, []libdns.Record{recordToDelete})
			deleteResults[id] = result
			deleteErrors[id] = err
		}(i)
	}

	deleteWg.Wait()

	// Verify all delete operations succeeded
	for i := range numGoroutines {
		if deleteErrors[i] != nil {
			t.Fatalf("Delete goroutine %d failed: %v", i, deleteErrors[i])
		}
		if len(deleteResults[i]) != 1 {
			t.Fatalf("Delete goroutine %d: expected 1 deleted record, got %d", i, len(deleteResults[i]))
		}
	}

	// Phase 5: Test mixed concurrent operations
	var mixedWg sync.WaitGroup
	mixedErrors := make([]error, 6)
	var mixedCreated []libdns.Record

	// Create some records concurrently
	for i := range 2 {
		mixedWg.Add(1)
		go func(id int) {
			defer mixedWg.Done()
			record := libdns.RR{
				Type: "TXT",
				Name: fmt.Sprintf("mixed-create-%d", id),
				Data: fmt.Sprintf("mixed-data-%d", id),
				TTL:  ttl,
			}
			result, err := p.AppendRecords(ctx, zone, []libdns.Record{record})
			if err == nil && len(result) > 0 {
				mixedCreated = append(mixedCreated, result[0])
			}
			mixedErrors[id] = err
		}(i)
	}

	// Get records concurrently while creating
	for i := 2; i < 4; i++ {
		mixedWg.Add(1)
		go func(id int) {
			defer mixedWg.Done()
			_, err := p.GetRecords(ctx, zone)
			mixedErrors[id] = err
		}(i)
	}

	// Set records concurrently
	for i := 4; i < 6; i++ {
		mixedWg.Add(1)
		go func(id int) {
			defer mixedWg.Done()
			record := libdns.RR{
				Type: "TXT",
				Name: fmt.Sprintf("mixed-set-%d", id-4),
				Data: fmt.Sprintf("mixed-set-data-%d", id-4),
				TTL:  ttl,
			}
			result, err := p.SetRecords(ctx, zone, []libdns.Record{record})
			if err == nil && len(result) > 0 {
				mixedCreated = append(mixedCreated, result[0])
			}
			mixedErrors[id] = err
		}(i)
	}

	mixedWg.Wait()

	// Verify all mixed operations succeeded
	for i := range 6 {
		if mixedErrors[i] != nil {
			t.Fatalf("Mixed operation %d failed: %v", i, mixedErrors[i])
		}
	}

	// Clean up any records created during mixed operations
	if len(mixedCreated) > 0 {
		cleanupRecords(t, ctx, p, mixedCreated)
	}
}
