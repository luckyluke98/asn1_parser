# ASN.1 and Encoding Rules

**ASN.1** is a language. It describes data structures but does not dictate how they are serialized into bytes. 

For example, here is a definition in ASN.1:

```asn1
Person ::= SEQUENCE {
    name UTF8String,
    age INTEGER
}
```

To transform ASN.1 definitions into actual bytes, **Encoding Rules** are required. Therefore, the data structure defined above can have multiple valid byte encodings depending on the rule used.  

For example, the data we receive in an SMB security blob is an ASN.1 structure serialized using a specific encoding rule.


## 1. Principal Encoding Rules

* **BER / DER / CER** (Basic Encoding Rules; Distinguished Encoding Rules; Canonical Encoding Rules): These belong to the **TLV** (Tag-Length-Value) family. They are widely used, including in protocols like SPNEGO and SMB.
* **PER** (Packed Encoding Rules)
* **OER** (Octet Encoding Rules)

### BER vs. DER
* **BER** allows multiple ways to encode the same value.
* **DER** is a strict subset of BER. It guarantees a single, unique encoding format for every value by strictly using definite lengths.

### ASN.1 DER Example

Here is a breakdown of a DER-encoded payload take from microsoft website:
> **References & Further Reading:** > [Introduction to ASN.1 Syntax and Encoding (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-introduction-to-asn-1-syntax-and-encoding)

```text
30 23                               ; SEQUENCE (0x23 = 35 Bytes)
|  |  31 0f                         ; SET (15 Bytes)
|  |  |  30 0d                      ; SEQUENCE (13 Bytes)
|  |  |     06 03                   ; OBJECT_ID (3 Bytes)
|  |  |     |  55 04 03             ; 2.5.4.3 Common Name (CN)
|  |  |     |     					
|  |  |     13 06                   ; PRINTABLE_STRING (6 Bytes)
|  |  |        54 65 73 74 43 4e    ; "TestCN"
|  |  |           					
|  |  31 10                         ; SET (16 Bytes)
|  |     30 0e                      ; SEQUENCE (14 Bytes)
|  |        06 03                   ; OBJECT_ID (3 Bytes)
|  |        |  55 04 0a             ; 2.5.4.10 Organization (O)
|  |        |     					
|  |        13 07                   ; PRINTABLE_STRING (7 Bytes)
|  |           54 65 73 74 4f 72 67 ; "TestOrg"
```


## 2. ASN.1 Tag Classes

To ensure encodings are unambiguous, every ASN.1 type is associated with a tag. A tag consists of two parts: the **class** and the **number**. The following classes are defined:

```
      7 6  5  4 3 2 1 0
TAG: |x|x||x||x|x|x|x|x|
     ^---^^-^^---------^
     |   |   |     
   Class | Number
        P/C
 
 Class:
  - 00 -> Universal
  - 01 -> Application
  - 10 -> Context-specif
  - 11 -> Private
```

* **UNIVERSAL:** Assigned to tags defined in the core ASN.1 standard.
* **APPLICATION:** Intended to uniquely identify a type within a specific application. Some application-layer standards use these tags extensively to name their types.
* **PRIVATE:** Used by organizations or companies to define types with private class tags for use across their internal/common applications.
* **Context-specific:** Used with types that only need to be identified within a specific, well-defined context (e.g., distinguishing a type within a sequence of other similar types).

> **References & Further Reading:** > [Encoded Tag Bytes (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-tag-bytes)


## 3. Transfer Syntax (TLV)

The transfer syntax used by these distinct encoding rules always follows a **Tag, Length, Value (TLV)** format. 

* **Tag (T):** Specifies the type of the data structure being sent.
* **Length (L):** Specifies the number of bytes of content to transfer.
* **Value (V):** Contains the actual content/data. 

Note that the *Value* field can itself be a TLV triplet if it contains a *Constructed* data type (like a Sequence or a Set), causing a nested structure. 

```text
+-------------------------------+
|   |   +---------------------+ |
|   |   |   |   +-----------+ | |
| T | L | T | L | T | L | V | | |
|   |   |   |   +-----------+ | |  
|   |   +---------------------+ |
+-------------------------------+
```
> **References & Further Reading:** > [DER Transfer Syntax (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-der-transfer-syntax)

## 4. Length Encoding Rules

The length field in a TLV triplet identifies the number of encoded bytes in the value field. 

**Short Form (Length <= 127 bytes):**
If the value field requires fewer than 128 bytes, the length field takes exactly 1 byte. Bit 7 is set to zero (`0`), and the remaining bits indicate the length.

```text
|0|0|1|1|0|1|0|0||x|x|x|x|x|x|x|x|x|x|x|x|x|x|...
 ^ ^-----------^  ^--------------------------^ 
 |  Length = 52           Value -> 52 Bytes
 |    
Bit for 0 <= Length <= 127 bytes
```

**Long Form (Length >= 128 bytes):**
If the value field requires more than 127 bytes, Bit 7 of the initial length byte is set to one (`1`). The remaining bits of that first byte indicate *how many subsequent bytes* are used to express the actual length value.

```text
|1|0|0|0|0|0|1|0||0|0|0|1|0|0|1|1|0|1|0|0|0|1|1|0||x|x|x|x|x|x|x|x|...
 ^ ^-----------^  ^-----------------------------^  ^---------------^
 | Num Of len = 2       2 Bytes -> 4934              Value -> 4934 Bytes
 |    
Bit for 128 <= Length <= 256^126 bytes
```
> **References & Further Reading:** > [Encoded Length and Value Bytes (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-length-and-value-bytes)


## 5. ASN.1 Data Types Reference

Below are the common Hex tags for various ASN.1 data types.

### Base Types

| Hex | Type | Hex | Type |
| :--- | :--- | :--- | :--- |
| `0x00` | EOC (End-of-Content) | `0x07` | ObjectDescriptor |
| `0x01` | BOOLEAN | `0x09` | REAL |
| `0x02` | INTEGER | `0x0d` | RELATIVE-OID |
| `0x03` | BIT_STRING | `0x17` | UTCTime |
| `0x04` | OCTET_STRING | `0x18` | GeneralizedTime |
| `0x05` | NULL | | |
| `0x06` | OBJECT_ID | | |

### String Types

| Hex | Type | Hex | Type |
| :--- | :--- | :--- | :--- |
| `0x0C` | UTF8_STRING | `0x19` | GraphicString |
| `0x12` | NumericString | `0x1a` | VisibleString |
| `0x13` | PRINTABLE_STRING | `0x1b` | GeneralString |
| `0x14` | T61String | `0x1c` | UniversalString |
| `0x15` | VideotexString | `0x1e` | UNICODE_STRING / BMPString |
| `0x16` | IA5_STRING | `0x3d` | CHARACTER_STRING |

### Constructed Types

| Hex | Type |
| :--- | :--- |
| `0x28` | EXTERNAL |
| `0x30` | Tag for SEQUENCE |
| `0x31` | Tag for SET |
| `0x0a` | Tag for ENUMERATED (positive INTEGERs only) |
| `0x2B` | EMBEDDED PDV |

> **References & Further Reading:** > [DER Encoding of ASN.1 Types (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types)