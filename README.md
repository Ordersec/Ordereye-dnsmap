
---
# Ordereye DNSMap

![order](https://github.com/user-attachments/assets/1619a99f-8719-4823-9ffa-e97a91dd301b)

> Part of the **Ordereye** cybersecurity reconnaissance toolkit.

**Ordereye DNSMap** is a fast, low-level DNS infrastructure mapping tool designed to enumerate and correlate DNS records in a structured and hierarchical way.

Built entirely in **C**, it focuses on performance, control, and clarity, allowing deep inspection of DNS relationships such as **NS → A/AAAA → PTR**, **MX → A/AAAA → PTR**, and more — all displayed in a clean, readable tree-like output.

---

## Features

* DNS enumeration for common record types:

  * `A`, `AAAA`, `NS`, `PTR`, `MX`, `CNAME`, `SOA`
* Hierarchical resolution and cascading queries:

  * NS → A / AAAA → PTR
  * MX → A / AAAA → PTR
* Clear, structured terminal output with visual hierarchy
* Built with raw DNS packets — no external resolver libraries
* Designed for scalability and large DNS surfaces

---

## Usage

```bash
./ordereye-dnsmap [options] [domain]
```

### Basic example

```bash
./ordereye-dnsmap wordlist.txt example.com
```

---

## Options

```text
-h        Show help
```

## Output Example

```
✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧

QUERY A of google.com

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧
✦ google.com
 ├─  172.217.29.238 ⟪ A | IN | 35 ⟫

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧

QUERY AAAA of google.com

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧
✦ google.com
 ├─  2800:3f0:4001:814::200e ⟪ AAAA | IN | 146 ⟫

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧

QUERY NS of google.com

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧
✦ google.com
 │   ├─ ns4.google.com ⟪ NS | IN | 343739 ⟫
 │     ├─ 216.239.38.10 ⟪ A | IN | 337234 ⟫
 │       └─ ns4.google.com ⟪ PTR | IN | 76173 ⟫
 │     └─ 2001:4860:4802:38::a ⟪ AAAA | IN | 345600 ⟫
 │   ├─ ns1.google.com ⟪ NS | IN | 343739 ⟫
 │     ├─ 216.239.32.10 ⟪ A | IN | 339581 ⟫
 │       └─ ns1.google.com ⟪ PTR | IN | 81173 ⟫
 │     └─ 2001:4860:4802:32::a ⟪ AAAA | IN | 343154 ⟫
 │   ├─ ns2.google.com ⟪ NS | IN | 343739 ⟫
 │     ├─ 216.239.34.10 ⟪ A | IN | 340198 ⟫
 │       └─ ns2.google.com ⟪ PTR | IN | 84929 ⟫
 │     └─ 2001:4860:4802:34::a ⟪ AAAA | IN | 338890 ⟫
 │   └─ ns3.google.com ⟪ NS | IN | 343739 ⟫
 │     ├─ 216.239.36.10 ⟪ A | IN | 335390 ⟫
 │       └─ ns3.google.com ⟪ PTR | IN | 82051 ⟫
 │     └─ 2001:4860:4802:36::a ⟪ AAAA | IN | 342637 ⟫

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧

QUERY MX of google.com

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧
✦ google.com
 │   └─ smtp.google.com ⟪ MX | IN | 222 ⟫
 │     ├─ 64.233.186.26 ⟪ A | IN | 119 ⟫
 │       └─ cb-in-f26.1e100.net ⟪ PTR | IN | 86400 ⟫
 │     ├─ 142.251.0.26 ⟪ A | IN | 119 ⟫
 │       └─ cj-in-f26.1e100.net ⟪ PTR | IN | 3600 ⟫
 │     ├─ 142.251.0.27 ⟪ A | IN | 119 ⟫
 │       └─ cj-in-f27.1e100.net ⟪ PTR | IN | 3600 ⟫
 │     ├─ 142.250.0.27 ⟪ A | IN | 119 ⟫
 │       └─ cg-in-f27.1e100.net ⟪ PTR | IN | 3600 ⟫
 │     ├─ 142.250.0.26 ⟪ A | IN | 119 ⟫
 │       └─ cg-in-f26.1e100.net ⟪ PTR | IN | 3600 ⟫
 │     ├─ 2800:3f0:4003:c03::1b ⟪ AAAA | IN | 145 ⟫
 │     ├─ 2800:3f0:4003:c03::1a ⟪ AAAA | IN | 145 ⟫
 │     ├─ 2800:3f0:4003:c08::1a ⟪ AAAA | IN | 145 ⟫
 │     └─ 2800:3f0:4003:c08::1b ⟪ AAAA | IN | 145 ⟫

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧

QUERY SOA of google.com

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧
✦ google.com
 ├─ MNAME: ns1.google.com (Primary Nameserver)
 ├─ RNAME: dns-admin.google.com (Responsible Person)
 ├─ SERIAL: 847693555 (Zone Version)
 ├─ REFRESH: 900 (Secondary NS refresh interval)
 ├─ RETRY: 900 (Retry interval on failure)
 ├─ EXPIRE: 1800 (Zone expiration time)
 └─ MINIMUM: 60 (Negative caching TTL)

✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧ ✦ ✧
```

---

## Design Philosophy

Ordereye DNSMap is not just a DNS query tool — it is designed to **map infrastructure relationships**, revealing how services are structured behind a domain.

Key goals:

* Predictable behavior
* Explicit control over every query
* No hidden abstractions
* Output that reflects real DNS hierarchy

This makes it ideal for **reconnaissance**, **attack surface mapping**, and **infrastructure analysis**.

---

## About

Ordereye DNSMap is part of the **Ordereye Toolkit**, a collection of cybersecurity reconnaissance tools developed by [Shinsuki](https://github.com/Ordersec).

---

## License

MIT

---
