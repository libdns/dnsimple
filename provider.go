package dnsimple

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with DNSimple.
type Provider struct {
	APIAccessToken string `json:"api_access_token,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	APIURL         string `json:"api_url,omitempty"`

	client dnsimple.Client
	once   sync.Once
	mutex  sync.Mutex
}

// initClient will initialize the DNSimple API client with the provided access token and
// store the client in the Provider struct, along with setting the API URL and Account ID.
func (p *Provider) initClient(ctx context.Context) {
	p.once.Do(func() {
		// Create new DNSimple client using the provided access token.
		tc := dnsimple.StaticTokenHTTPClient(ctx, p.APIAccessToken)
		c := *dnsimple.NewClient(tc)
		// Set the API URL if using a non-default API hostname (e.g. sandbox).
		if p.APIURL != "" {
			c.BaseURL = p.APIURL
		}
		// If no Account ID is provided, we can call the API to get the corresponding
		// account id for the provided access token.
		if p.AccountID == "" {
			resp, _ := c.Identity.Whoami(context.Background())
			accountID := strconv.FormatInt(resp.Data.Account.ID, 10)
			p.AccountID = accountID
		}

		p.client = c
	})
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.initClient(ctx)

	var records []libdns.Record

	resp, err := p.client.Zones.ListRecords(ctx, p.AccountID, zone, &dnsimple.ZoneRecordListOptions{})
	if err != nil {
		return nil, err
	}
	for _, r := range resp.Data {
		records = append(records, libdns.Record{
			ID:       strconv.FormatInt(r.ID, 10),
			Type:     r.Type,
			Name:     r.Name,
			Value:    r.Content,
			TTL:      time.Duration(r.TTL),
			Priority: uint(r.Priority),
		})
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.initClient(ctx)

	return nil, fmt.Errorf("TODO: not implemented")
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.initClient(ctx)

	return nil, fmt.Errorf("TODO: not implemented")
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.initClient(ctx)

	return nil, fmt.Errorf("TODO: not implemented")
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
