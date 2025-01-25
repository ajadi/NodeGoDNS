package dnsserver

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "time"

    "github.com/miekg/dns"
    "github.com/ajadi/NodeGoDNS/models"
)

/*
SignRRset is our custom DNSSEC signing function that produces RRSIG records
for an RRset using RSASHA256 (Algorithm=8). This is a simplified approach
demonstrating the RFC 4034/4035 essential steps.
*/
func SignRRset(rrset []dns.RR, soa models.SOA, dnskey models.DNSKEY, key *rsa.PrivateKey) ([]*dns.RRSIG, error) {
    if len(rrset) == 0 {
        return nil, nil
    }

    // We assume the entire rrset shares the same name and type
    name := rrset[0].Header().Name
    rtype := rrset[0].Header().Rrtype

    labels := computeLabels(name)

    // Minimal inception / expiration
    inception := uint32(time.Now().Unix())
    expiration := uint32(time.Now().Add(24 * time.Hour).Unix())

    // Build the RRSIG record
    rrsig := &dns.RRSIG{
        Hdr: dns.RR_Header{
            Name:   name,
            Rrtype: dns.TypeRRSIG,
            Class:  dns.ClassINET,
            Ttl:    soa.TTL,
        },
        TypeCovered: rtype,
        Algorithm:   dnskey.Algorithm, // e.g. 8 = RSASHA256
        Labels:      labels,
        OriginalTtl: soa.TTL,
        Expiration:  expiration,
        Inception:   inception,
        KeyTag:      calcKeyTag(dnskey),
        SignerName:  dnskey.Name,
        Signature:   "",
    }

    // Wire data for RRSIG per RFC 4034
    wireData, err := buildRRSIGWireData(rrset, rrsig)
    if err != nil {
        return nil, err
    }

    // Compute digest with SHA256
    h := sha256.New()
    _, _ = h.Write(wireData)
    digest := h.Sum(nil)

    // RSA sign
    sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
    if err != nil {
        return nil, fmt.Errorf("SignPKCS1v15: %w", err)
    }

    // Base64 encode signature
    rrsig.Signature = singleLineBase64(base64.StdEncoding.EncodeToString(sig))

    return []*dns.RRSIG{rrsig}, nil
}

// buildRRSIGWireData constructs the data that is hashed, per RFC 4034
func buildRRSIGWireData(rrset []dns.RR, rrsig *dns.RRSIG) ([]byte, error) {
    // 1) RRSIG RDATA fields (except the Signature itself)
    // 2) canonical form of each RR in the set
    wire := make([]byte, 0, 1024)

    // TypeCovered (2 bytes)
    wire = appendUint16(wire, rrsig.TypeCovered)
    // Algorithm (1)
    wire = append(wire, rrsig.Algorithm)
    // Labels (1)
    wire = append(wire, rrsig.Labels)
    // OriginalTTL (4)
    wire = appendUint32(wire, rrsig.OriginalTtl)
    // Expiration (4)
    wire = appendUint32(wire, rrsig.Expiration)
    // Inception (4)
    wire = appendUint32(wire, rrsig.Inception)
    // KeyTag (2)
    wire = appendUint16(wire, rrsig.KeyTag)
    // SignerName in DNS wire format
    nm, err := dns.NewNameCompiler(rrsig.SignerName).Type(dns.StringType).Pack()
    if err != nil {
        return nil, err
    }
    wire = append(wire, nm...)

    // Then each RR in canonical form
    for _, rr := range rrset {
        b, err := dns.PackRR(rr, dns.PackConfig{})
        if err != nil {
            return nil, err
        }
        wire = append(wire, b...)
    }
    return wire, nil
}

func computeLabels(name string) uint8 {
    if name == "." {
        return 0
    }
    s := dns.Fqdn(name)
    return uint8(dns.CountLabel(s))
}

func calcKeyTag(dnskey models.DNSKEY) uint16 {
    // Minimal key tag approach
    pk := []byte(dnskey.PublicKey)
    var sum int
    for i := 0; i < len(pk); i++ {
        if (i % 2) == 0 {
            sum += int(pk[i]) << 8
        } else {
            sum += int(pk[i])
        }
    }
    sum = (sum & 0xFFFF) + (sum >> 16)
    return uint16(sum & 0xFFFF)
}

// Helpers for appending numeric fields
func appendUint16(b []byte, v uint16) []byte {
    return append(b, byte(v>>8), byte(v))
}
func appendUint32(b []byte, v uint32) []byte {
    return append(b,
        byte((v>>24)&0xFF),
        byte((v>>16)&0xFF),
        byte((v>>8)&0xFF),
        byte(v&0xFF),
    )
}

// singleLineBase64 ensures the signature is on a single line
func singleLineBase64(sig string) string {
    return sig
}
