package dnsserver

import (
    "crypto/rsa"
    "fmt"
    "net"
    "strings"
    "sync"
    "time"

    "github.com/miekg/dns"
    "github.com/sirupsen/logrus"
    "github.com/ajadi/NodeGoDNS/cache"
    "github.com/ajadi/NodeGoDNS/models"
    "github.com/ajadi/NodeGoDNS/utils"
)

// DNSServer is responsible for handling DNS queries.
// We implement a custom DNSSEC logic in dnssec.go, not relying on github.com/miekg/dns/dnssec.
type DNSServer struct {
    Zones           map[string]models.Zone
    ZonesMutex      *sync.RWMutex
    Cache           *cache.DNSCache
    ZSK             *rsa.PrivateKey
    KSK             *rsa.PrivateKey
    DynamicUpdate   bool
    AllowedNetworks []string
}

// NewDNSServer creates a DNSServer instance.
func NewDNSServer(
    zones map[string]models.Zone,
    zonesMutex *sync.RWMutex,
    cacheSvc *cache.DNSCache,
    zsk, ksk *rsa.PrivateKey,
    dynamicUpdate bool,
    allowedNetworks []string,
) *DNSServer {
    return &DNSServer{
        Zones:           zones,
        ZonesMutex:      zonesMutex,
        Cache:           cacheSvc,
        ZSK:             zsk,
        KSK:             ksk,
        DynamicUpdate:   dynamicUpdate,
        AllowedNetworks: allowedNetworks,
    }
}

// ServeDNS handles incoming DNS queries.
func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
    m := new(dns.Msg)
    m.SetReply(r)
    m.Compress = true

    for _, q := range r.Question {
        cacheKey := fmt.Sprintf("%s:%d", q.Name, q.Qtype)
        if cachedResponse, found := s.Cache.Get(cacheKey); found {
            if msg, ok := cachedResponse.(*dns.Msg); ok {
                m.Answer = append(m.Answer, msg.Answer...)
                m.Ns = append(m.Ns, msg.Ns...)
                m.Extra = append(m.Extra, msg.Extra...)
                _ = w.WriteMsg(m)
                logrus.WithFields(logrus.Fields{
                    "cache_key": cacheKey,
                    "type":      dns.TypeToString[q.Qtype],
                }).Info("Cached response sent")
                continue
            }
        }

        zoneName := s.findZone(q.Name)
        if zoneName == "" {
            m.Rcode = dns.RcodeNameError
            _ = w.WriteMsg(m)
            logrus.WithFields(logrus.Fields{
                "query": q.Name,
                "type":  dns.TypeToString[q.Qtype],
            }).Warn("No matching zone found for query")
            continue
        }

        s.ZonesMutex.RLock()
        zone, exists := s.Zones[zoneName]
        s.ZonesMutex.RUnlock()
        if !exists {
            m.Rcode = dns.RcodeNameError
            _ = w.WriteMsg(m)
            logrus.WithFields(logrus.Fields{
                "zone":  zoneName,
                "query": q.Name,
                "type":  dns.TypeToString[q.Qtype],
            }).Warn("Zone does not exist")
            continue
        }

        var response []dns.RR

        switch q.Qtype {
        case dns.TypeDNSKEY:
            // Return DNSKEY from zone
            response = toDNSKEYRR(zone.DNSKEY)
            // Sign the DNSKEY RR set with KSK
            rrsigs, err := s.customSignRRset(response, zoneName, true)
            if err != nil {
                logrus.WithFields(logrus.Fields{"error": err}).Error("Failed to sign DNSKEY RRset")
                m.Rcode = dns.RcodeServerFailure
                _ = w.WriteMsg(m)
                continue
            }
            response = append(response, rrsigs...)

        case dns.TypeAXFR, dns.TypeIXFR:
            // Zone transfer not implemented
            m.Rcode = dns.RcodeNotImplemented
            _ = w.WriteMsg(m)
            logrus.WithFields(logrus.Fields{"query": q.Name, "type": dns.TypeToString[q.Qtype]}).
                Warn("Zone transfer not implemented")
            continue

        default:
            answers, err := s.handleQuery(q, zone)
            if err != nil {
                m.Rcode = dns.RcodeServerFailure
                _ = w.WriteMsg(m)
                logrus.WithFields(logrus.Fields{
                    "error": err,
                    "query": q.Name,
                    "type":  dns.TypeToString[q.Qtype],
                }).Error("Error processing query")
                continue
            }
            // sign with ZSK
            rrsigs, err := s.customSignRRset(answers, zoneName, false)
            if err != nil {
                m.Rcode = dns.RcodeServerFailure
                _ = w.WriteMsg(m)
                logrus.WithFields(logrus.Fields{"error": err}).Error("Failed to sign RRset")
                continue
            }
            response = append(response, answers...)
            response = append(response, rrsigs...)

            expSec := time.Duration(getMinTTL(response)) * time.Second
            cachedMsg := m.Copy()
            cachedMsg.Answer = response
            s.Cache.Set(cacheKey, cachedMsg, expSec)
        }

        m.Answer = append(m.Answer, response...)
        _ = w.WriteMsg(m)
        logrus.WithFields(logrus.Fields{
            "query": q.Name,
            "type":  dns.TypeToString[q.Qtype],
        }).Info("Query processed successfully")
    }
}

// handleQuery returns the requested RRset from the zone data.
func (s *DNSServer) handleQuery(q dns.Question, zone models.Zone) ([]dns.RR, error) {
    var answers []dns.RR
    switch q.Qtype {
    case dns.TypeA:
        if ip, exists := zone.A[q.Name]; exists {
            aRecord := &dns.A{
                Hdr: dns.RR_Header{
                    Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: zone.SOA.TTL,
                },
                A: net.ParseIP(ip),
            }
            answers = append(answers, aRecord)
        }
    case dns.TypeAAAA:
        if ip, exists := zone.AAAA[q.Name]; exists {
            aaaaRecord := &dns.AAAA{
                Hdr: dns.RR_Header{
                    Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: zone.SOA.TTL,
                },
                AAAA: net.ParseIP(ip),
            }
            answers = append(answers, aaaaRecord)
        }
    case dns.TypeMX:
        for _, mx := range zone.MX {
            mxRecord := &dns.MX{
                Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: zone.SOA.TTL},
                Preference: mx.Priority,
                Mx:         mx.Target,
            }
            answers = append(answers, mxRecord)
        }
    case dns.TypeTXT:
        if txt, exists := zone.TXT[q.Name]; exists {
            txtRecord := &dns.TXT{
                Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: zone.SOA.TTL},
                Txt: []string{txt},
            }
            answers = append(answers, txtRecord)
        }
    case dns.TypeCNAME:
        if target, exists := zone.CNAME[q.Name]; exists {
            cnameRecord := &dns.CNAME{
                Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: zone.SOA.TTL},
                Target: target,
            }
            answers = append(answers, cnameRecord)
        }
    case dns.TypeSRV:
        for _, srv := range zone.SRV {
            srvRecord := &dns.SRV{
                Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: zone.SOA.TTL},
                Priority: srv.Priority,
                Weight:   srv.Weight,
                Port:     srv.Port,
                Target:   srv.Target,
            }
            answers = append(answers, srvRecord)
        }
    case dns.TypePTR:
        if ptr, exists := zone.PTR[q.Name]; exists {
            ptrRecord := &dns.PTR{
                Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: zone.SOA.TTL},
                Ptr: ptr,
            }
            answers = append(answers, ptrRecord)
        }
    default:
        return nil, fmt.Errorf("unsupported query type: %d", q.Qtype)
    }
    return answers, nil
}

// findZone attempts to match a domain to a known zone name.
func (s *DNSServer) findZone(domain string) string {
    s.ZonesMutex.RLock()
    defer s.ZonesMutex.RUnlock()
    for zoneName := range s.Zones {
        if utils.IsSubDomain(zoneName, domain) {
            return zoneName
        }
    }
    return ""
}

func getMinTTL(rrs []dns.RR) uint32 {
    min := uint32(3600)
    for _, rr := range rrs {
        if rr.Header().Ttl < min {
            min = rr.Header().Ttl
        }
    }
    return min
}

// customSignRRset references our custom DNSSEC logic in dnssec.go
func (s *DNSServer) customSignRRset(rrset []dns.RR, zoneName string, isDNSKEY bool) ([]dns.RR, error) {
    s.ZonesMutex.RLock()
    zone, ok := s.Zones[zoneName]
    s.ZonesMutex.RUnlock()
    if !ok {
        return nil, fmt.Errorf("zone not found: %s", zoneName)
    }

    var privateKey *rsa.PrivateKey
    var signerKey models.DNSKEY
    if isDNSKEY {
        // KSK
        for _, key := range zone.DNSKEY {
            if key.Flags&257 == 257 {
                signerKey = key
                privateKey = s.KSK
                break
            }
        }
    } else {
        // ZSK
        for _, key := range zone.DNSKEY {
            if key.Flags&256 == 256 {
                signerKey = key
                privateKey = s.ZSK
                break
            }
        }
    }
    if privateKey == nil {
        return nil, fmt.Errorf("no suitable private key (ZSK/KSK) found for zone %s", zoneName)
    }

    rrsigs, err := SignRRset(rrset, zone.SOA, signerKey, privateKey)
    if err != nil {
        return nil, fmt.Errorf("error signing rrset: %w", err)
    }

    var out []dns.RR
    for _, sig := range rrsigs {
        out = append(out, sig)
    }
    return out, nil
}

// toDNSKEYRR converts NodeGoDNS's DNSKEY model to miekg/dns DNSKEY records
func toDNSKEYRR(dnskeys []models.DNSKEY) []dns.RR {
    var result []dns.RR
    for _, k := range dnskeys {
        rr := &dns.DNSKEY{
            Hdr: dns.RR_Header{
                Name:   k.Name,
                Rrtype: dns.TypeDNSKEY,
                Class:  dns.ClassINET,
                Ttl:    3600,
            },
            Flags:     k.Flags,
            Protocol:  k.Protocol,
            Algorithm: k.Algorithm,
            PublicKey: k.PublicKey,
        }
        result = append(result, rr)
    }
    return result
}

// StartDNSServer starts a UDP DNS server on the specified address.
func StartDNSServer(server *DNSServer, addr string) error {
    dns.HandleFunc(".", server.ServeDNS)
    dnsServer := &dns.Server{Addr: addr, Net: "udp"}

    go func() {
        logrus.WithFields(logrus.Fields{"addr": addr}).Info("DNS server started (NodeGoDNS)")
        if err := dnsServer.ListenAndServe(); err != nil {
            logrus.WithFields(logrus.Fields{"error": err, "addr": addr}).
                Fatal("Error starting DNS server")
        }
    }()

    return nil
}
