package main

// BIAC binary format (v1): compact, deterministic, single-pass loadable.
//
//	"BIAC" | ver u8 | flags u8 (0)
//	uvarint nStrings | uvarint blobLen | nStrings x uvarint len | blob (UTF-8)
//	root value
//	sha256 (32 bytes) over everything before it   -- integrity, not authenticity
//
// Every string (object keys AND string values) lives once in the string table,
// ordered by descending frequency so hot strings get 1-byte references.
// Value tags: 0 null | 1 false | 2 true | 3 int(zigzag uvarint) | 4 float64(8B LE)
//             5 string(ref) | 6 array(n, values) | 7 object(n, (keyRef, value)...)
// Object keys are sorted, so identical input yields identical bytes.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
)

var binMagic = []byte("BIAC")

const (
	tNull = iota
	tFalse
	tTrue
	tInt
	tFloat
	tString
	tArray
	tObject

	maxDepth = 64
)

// ---------- encode ----------

func encodeBin(root any) ([]byte, error) {
	freq := map[string]int{}
	if err := countStrings(root, freq, 0); err != nil {
		return nil, err
	}
	strs := make([]string, 0, len(freq))
	for s := range freq {
		strs = append(strs, s)
	}
	sort.Slice(strs, func(i, j int) bool {
		if freq[strs[i]] != freq[strs[j]] {
			return freq[strs[i]] > freq[strs[j]]
		}
		return strs[i] < strs[j]
	})
	idx := make(map[string]uint64, len(strs))
	blobLen := 0
	for i, s := range strs {
		idx[s] = uint64(i)
		blobLen += len(s)
	}

	var b bytes.Buffer
	b.Write(binMagic)
	b.WriteByte(1)
	b.WriteByte(0)
	putU(&b, uint64(len(strs)))
	putU(&b, uint64(blobLen))
	for _, s := range strs {
		putU(&b, uint64(len(s)))
	}
	for _, s := range strs {
		b.WriteString(s)
	}
	if err := writeVal(&b, root, idx, 0); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b.Bytes())
	b.Write(sum[:])
	return b.Bytes(), nil
}

func countStrings(v any, freq map[string]int, d int) error {
	if d > maxDepth {
		return errors.New("nesting too deep")
	}
	switch x := v.(type) {
	case string:
		freq[x]++
	case []any:
		for _, e := range x {
			if err := countStrings(e, freq, d+1); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, e := range x {
			freq[k]++
			if err := countStrings(e, freq, d+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeVal(b *bytes.Buffer, v any, idx map[string]uint64, d int) error {
	switch x := v.(type) {
	case nil:
		b.WriteByte(tNull)
	case bool:
		if x {
			b.WriteByte(tTrue)
		} else {
			b.WriteByte(tFalse)
		}
	case json.Number:
		if i, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			b.WriteByte(tInt)
			putU(b, zig(i))
		} else if f, err := x.Float64(); err == nil {
			b.WriteByte(tFloat)
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], math.Float64bits(f))
			b.Write(buf[:])
		} else {
			return fmt.Errorf("bad number %q", x)
		}
	case string:
		b.WriteByte(tString)
		putU(b, idx[x])
	case []any:
		b.WriteByte(tArray)
		putU(b, uint64(len(x)))
		for _, e := range x {
			if err := writeVal(b, e, idx, d+1); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte(tObject)
		putU(b, uint64(len(keys)))
		for _, k := range keys {
			putU(b, idx[k])
			if err := writeVal(b, x[k], idx, d+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported type %T (normalize via JSON first)", v)
	}
	return nil
}

func putU(b *bytes.Buffer, u uint64) {
	var buf [binary.MaxVarintLen64]byte
	b.Write(buf[:binary.PutUvarint(buf[:], u)])
}

func zig(i int64) uint64   { return uint64(i<<1) ^ uint64(i>>63) }
func unzig(u uint64) int64 { return int64(u>>1) ^ -int64(u&1) }

// ---------- decode (input is untrusted: every length is bounds-checked) ----------

type reader struct {
	b    []byte
	p    int
	strs []string
}

var errTrunc = errors.New("corrupt or truncated artifact")

func (r *reader) uvar() (uint64, error) {
	v, n := binary.Uvarint(r.b[r.p:])
	if n <= 0 {
		return 0, errTrunc
	}
	r.p += n
	return v, nil
}

func decodeBin(data []byte) (any, error) {
	if len(data) < len(binMagic)+2+32 || !bytes.Equal(data[:4], binMagic) {
		return nil, errors.New("not a BIAC binary artifact")
	}
	if data[4] != 1 {
		return nil, fmt.Errorf("unsupported BIAC binary version %d", data[4])
	}
	body, want := data[:len(data)-32], data[len(data)-32:]
	if got := sha256.Sum256(body); !bytes.Equal(got[:], want) {
		return nil, errors.New("checksum mismatch: artifact is corrupted or modified")
	}
	r := &reader{b: body, p: 6}
	n, err := r.uvar()
	if err != nil {
		return nil, err
	}
	blobLen, err := r.uvar()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(body)) || blobLen > uint64(len(body)) { // each string costs >= 1 byte
		return nil, errTrunc
	}
	lens := make([]uint64, n)
	var total uint64
	for i := range lens {
		if lens[i], err = r.uvar(); err != nil {
			return nil, err
		}
		total += lens[i]
		if total > blobLen {
			return nil, errTrunc
		}
	}
	if total != blobLen || uint64(len(body)-r.p) < blobLen {
		return nil, errTrunc
	}
	blob := string(body[r.p : r.p+int(blobLen)]) // one allocation; strings below are substrings
	r.p += int(blobLen)
	r.strs = make([]string, n)
	off := 0
	for i, l := range lens {
		r.strs[i] = blob[off : off+int(l)]
		off += int(l)
	}
	v, err := r.val(0)
	if err != nil {
		return nil, err
	}
	if r.p != len(body) {
		return nil, errors.New("trailing data in artifact")
	}
	return v, nil
}

func (r *reader) str() (string, error) {
	i, err := r.uvar()
	if err != nil || i >= uint64(len(r.strs)) {
		return "", errTrunc
	}
	return r.strs[i], nil
}

func (r *reader) val(d int) (any, error) {
	if d > maxDepth {
		return nil, errors.New("nesting too deep")
	}
	if r.p >= len(r.b) {
		return nil, errTrunc
	}
	t := r.b[r.p]
	r.p++
	switch t {
	case tNull:
		return nil, nil
	case tFalse:
		return false, nil
	case tTrue:
		return true, nil
	case tInt:
		u, err := r.uvar()
		return unzig(u), err
	case tFloat:
		if r.p+8 > len(r.b) {
			return nil, errTrunc
		}
		f := math.Float64frombits(binary.LittleEndian.Uint64(r.b[r.p:]))
		r.p += 8
		return f, nil
	case tString:
		return r.str()
	case tArray:
		n, err := r.uvar()
		if err != nil || n > uint64(len(r.b)-r.p) {
			return nil, errTrunc
		}
		out := make([]any, n)
		for i := range out {
			if out[i], err = r.val(d + 1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case tObject:
		n, err := r.uvar()
		if err != nil || n > uint64(len(r.b)-r.p) {
			return nil, errTrunc
		}
		out := make(map[string]any, n)
		for i := uint64(0); i < n; i++ {
			k, err := r.str()
			if err != nil {
				return nil, err
			}
			if out[k], err = r.val(d + 1); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown tag %d", t)
}

// ---------- artifact I/O (format chosen by extension or sniffed on read) ----------

// normalize converts any Go value to the generic JSON tree (ints as json.Number).
func normalize(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	return out, dec.Decode(&out)
}

// loadArtifact reads .biac, .json or .json.gz (sniffed by content, not extension).
// This is the entry point the importer should use.
func loadArtifact(path string) (map[string]any, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > 1<<30 {
		return nil, errors.New("artifact larger than 1 GiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		if data, err = io.ReadAll(io.LimitReader(zr, 1<<30)); err != nil {
			return nil, err
		}
	}
	var v any
	if bytes.HasPrefix(data, binMagic) {
		v, err = decodeBin(data)
	} else {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err = dec.Decode(&v); err == nil {
			v = unNumber(v) // same Go types as the binary path: int64 / float64
		}
	}
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("artifact root must be an object")
	}
	return m, nil
}

func unNumber(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	case []any:
		for i := range x {
			x[i] = unNumber(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = unNumber(x[k])
		}
	}
	return v
}
