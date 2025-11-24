# Trust Issues [_snakeCTF 2025 Finals_]

**Category**: Web
**Author**: lilvirgola

## Description

After last month's security incident, our admin has serious trust issues. 
He changed all his passwords and started keeping them in "secure" locations. 
We've captured some network traffic from his paranoia-driven security overhaul.
The admin claims our new authentication system is "bulletproof" because it uses JWT tokens and a SQLite database. But something about the way he accesses his secrets makes us wonder...

Can you find what he's hiding?

### Hints

- Sometimes there is a strange metadata parameter, can this be some debug feature?

## Solution

The challenge involves exploiting a gRPC service with multiple vulnerabilities. The solution can be divided into several key steps: reconstructing the protocol buffer definitions from network traffic, discovering authentication credentials, exploiting an IDOR vulnerability, and finally leveraging SQL injection to extract the flag.

### Step 1: Protocol Reconstruction from PCAP

The challenge begins with a packet capture file containing plaintext gRPC traffic. By analysing the captured HTTP/2 frames, the service structure can be reconstructed.

From the pcap, the following information can be extracted:

1. **Service and RPC names** - visible in HTTP/2 `:path` headers (e.g., `/challenge.SecretsService/Login`)
2. **Field numbers** - encoded in the protobuf wire format
3. **Field values** - actual data transmitted in requests and responses
4. **Wire types** - distinguishing between varints, length-delimited fields, etc.

Using tools such as Wireshark's protobuf dissector or manual analysis, a minimal `.proto` file can be reconstructed, like the one presented [Here](./attachments/minimal.proto).

Note that field names must be inferred from context, as they are not transmitted in the wire format. However, the field numbers (which are critical for compatibility) are preserved.

### Step 2: Credential Discovery

By examining the login traffic in the pcap, at least one set of valid credentials can be discovered. The captured traffic reveals:

- **Username**: `alice`
- **Password**: `YWI4NmEyMTdiYmJmMDZjZGYxYjg2MWVhMGM0MGJjYjdkMTJjZmQ3NjRiYWVhZTkzZTJlOTI2ZGE2ZTAxMjM5MAo`

Upon successful authentication, a JWT token is returned which can be used for subsequent authenticated requests.

### Step 3: Discovering the Debug Header

By carefully analysing the pcap traffic, an unusual gRPC metadata header can be identified: `x-upstream-subject`.
This header appears to be a debug or internal routing mechanism, likely intended for use by trusted upstream services. The value is base64-encoded and follows the format:

```
base64(username + "|" + padding)
```

When this header is present, the server appears to trust it and uses the specified username for authorisation checks, bypassing normal JWT validation.

### Step 4: IDOR Exploitation via Header Injection

With Alice's credentials, the exploit can be constructed:

1. Authenticate as Alice to obtain a valid JWT token
2. List Alice's own resources to verify normal functionality
3. Add the `x-upstream-subject` header with value `base64("admin|...")` to the request context
4. List the admin's resources using the modified context

The server, trusting the `x-upstream-subject` header, returns the admin's resource list, revealing a resource ID: `admin-flag-store`.

An attempt can be made to access this resource directly using the same header injection technique. However, whilst the listing operation succeeds, direct access to the resource may be blocked by additional authorisation checks.

### Step 5: SQL Injection

Further analysis reveals that the `GetSecret` RPC is vulnerable to SQL injection through the `resource_id` parameter. The backend appears to construct a query similar to:

```sql
SELECT owner, secret, created FROM resources WHERE id='<resource_id>'
```
And then checks if the JWT user is equal to the resource owner.

By crafting a UNION-based SQL injection payload, the owner check can be bypassed:

```
nonexistent' UNION SELECT 'alice', secret, strftime('%s', created_at) FROM resources WHERE id='admin-flag-store' -- 
```

This payload:
1. Closes the original query with `nonexistent'` (a non-existent resource)
2. Uses `UNION SELECT` to inject a second query
3. Returns `'alice'` as the owner (matching the current authenticated user)
4. Extracts the `secret` from the `admin-flag-store` resource
5. Comments out the remainder of the query with `--`

When this payload is submitted via Alice's authenticated session, the server executes the injected query and returns the admin's flag.

[Here](./attachments/solve.go) is the solver code.

### Flag Retrieval

Upon successful exploitation, the flag is retrieved from the admin's secret store:

```
snakeCTF{gRPC_5ql_1nj3ct10n_15_r34l_ez}
```