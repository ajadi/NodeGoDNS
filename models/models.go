package models

// We store data structures for DNS zone, DNSKEY, etc.
// "github.com/miekg/dns" is used in other packages, but not imported here.

type Zone struct {
    SOA     SOA               `json:"soa"`
    NS      []string          `json:"ns"`
    A       map[string]string `json:"a"`
    AAAA    map[string]string `json:"aaaa"`
    MX      []MX              `json:"mx"`
    TXT     map[string]string `json:"txt"`
    CNAME   map[string]string `json:"cname"`
    SRV     []SRV             `json:"srv"`
    PTR     map[string]string `json:"ptr"`
    DNSKEY  []DNSKEY          `json:"dnskey"`
    RRSIG   []*RRSIG          `json:"rrsig"`
}

type SOA struct {
    Mname   string `json:"mname"`
    Rname   string `json:"rname"`
    Serial  uint32 `json:"serial"`
    Refresh uint32 `json:"refresh"`
    Retry   uint32 `json:"retry"`
    Expire  uint32 `json:"expire"`
    TTL     uint32 `json:"ttl"`
}

type MX struct {
    Priority uint16 `json:"priority"`
    Target   string `json:"target"`
}

type SRV struct {
    Priority uint16 `json:"priority"`
    Weight   uint16 `json:"weight"`
    Port     uint16 `json:"port"`
    Target   string `json:"target"`
}

type DNSKEY struct {
    Name      string `json:"name"`
    Flags     uint16 `json:"flags"`
    Protocol  uint8  `json:"protocol"`
    Algorithm uint8  `json:"algorithm"`
    PublicKey string `json:"public_key"`
}

type RRSIG struct {
    TypeCovered  uint16 `json:"type_covered"`
    Algorithm    uint8  `json:"algorithm"`
    Labels       uint8  `json:"labels"`
    OriginalTTL  uint32 `json:"original_ttl"`
    Expiration   uint32 `json:"expiration"`
    Inception    uint32 `json:"inception"`
    KeyTag       uint16 `json:"key_tag"`
    SignerName   string `json:"signer_name"`
    Signature    string `json:"signature"`
}

type User struct {
    ID        int    `json:"id"`
    Username  string `json:"username"`
    Password  string `json:"password"`
    CreatedAt string `json:"created_at"`
}
