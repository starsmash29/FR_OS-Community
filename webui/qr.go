package webui

import (
	"errors"
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"unicode/utf8"
)

// A QR Code encoder and its SVG, as 1.x makes them with segno 1.6.6:
// segno.make(text, error="m").save(kind="svg", scale=..., dark=..., light=...,
// xmldecl=False). The authenticator-app code on the TOTP enrolment page
// and the WireGuard client code are compared with 1.x's byte for byte, so
// this follows segno's choices, quirks included: one segment in the
// first mode that fits the whole text, the smallest version for level M,
// the level then raised as far as that version allows, every mask scored
// as segno scores it, and the path segno writes.
//
// Not ported, and refused rather than drawn differently: Micro QR Codes
// (segno picks one for text of a few characters; an otpauth:// URI or a
// WireGuard config is far longer), and text Latin-1 can't hold (segno
// tries Shift_JIS, then UTF-8; usernames and hosts here are ASCII).

const (
	qrLevelL = iota
	qrLevelM
	qrLevelQ
	qrLevelH
)

type qrBlockGroup struct{ blocks, total, data int }

// qrFormatLevel is the level's two format bits (M=0, L=1, H=2, Q=3).
var qrFormatLevel = [4]int{qrLevelL: 1, qrLevelM: 0, qrLevelQ: 3, qrLevelH: 2}

var errQRUnsupported = errors.New("qr: text needs a Micro QR Code or a non-Latin-1 encoding")

const (
	qrModeNumeric = 1
	qrModeAlnum   = 2
	qrModeByte    = 4
	qrModeKanji   = 8
)

var qrAlnumChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

var qrAlnumRE = regexp.MustCompile(`\A[0-9A-Z $%*+\-./:]+\z`)

type bits []byte

func (b *bits) add(v, n int) {
	for i := n - 1; i >= 0; i-- {
		*b = append(*b, byte(v>>i&1))
	}
}

// qrCountBits is the character count indicator's length by mode and
// version range (1-9, 10-26, 27-40).
func qrCountBits(mode, version int) int {
	r := 0
	switch {
	case version >= 27:
		r = 2
	case version >= 10:
		r = 1
	}
	return map[int][3]int{qrModeNumeric: {10, 12, 14}, qrModeAlnum: {9, 11, 13}, qrModeByte: {8, 16, 16},
		qrModeKanji: {8, 10, 12}}[mode][r]
}

func qrCapacity(version, level int) int {
	n := 0
	for _, g := range qrBlocks[version][level] {
		n += g.blocks * g.data
	}
	return n * 8
}

// qrSegment is segno's make_segment for text in the default encoding.
func qrSegment(text string) (mode int, data bits, count int, err error) {
	raw := make([]byte, 0, len(text))
	for _, r := range text {
		if r > 0xff || r == utf8.RuneError {
			return 0, nil, 0, errQRUnsupported
		}
		raw = append(raw, byte(r))
	}
	switch {
	case len(raw) > 0 && strings.Trim(string(raw), "0123456789") == "":
		mode = qrModeNumeric
		for i := 0; i < len(raw); i += 3 {
			chunk := raw[i:min(i+3, len(raw))]
			n := 0
			for _, c := range chunk {
				n = n*10 + int(c-'0')
			}
			data.add(n, len(chunk)*3+1)
		}
	case qrAlnumRE.Match(raw):
		mode = qrModeAlnum
		for i := 0; i < len(raw); i += 2 {
			if i+1 < len(raw) {
				data.add(strings.IndexByte(qrAlnumChars, raw[i])*45+strings.IndexByte(qrAlnumChars, raw[i+1]), 11)
			} else {
				data.add(strings.IndexByte(qrAlnumChars, raw[i]), 6)
			}
		}
	case qrKanji(raw):
		return 0, nil, 0, errQRUnsupported
	default:
		mode = qrModeByte
		for _, c := range raw {
			data.add(int(c), 8)
		}
	}
	return mode, data, len(raw), nil
}

func qrKanji(raw []byte) bool {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return false
	}
	for i := 0; i < len(raw); i += 2 {
		code := int(raw[i])<<8 | int(raw[i+1])
		if !(0x8140 <= code && code <= 0x9ffc || 0xe040 <= code && code <= 0xebbf) {
			return false
		}
	}
	return true
}

// qrMicroFits: segno would make a Micro QR Code (M2-M4 at level M).
func qrMicroFits(mode, dataBits int) bool {
	type micro struct{ modeBits, capacity int }
	// Level M: M2 has numeric and alphanumeric, M3 and M4 every mode.
	countBits := map[int][3]int{qrModeNumeric: {4, 5, 6}, qrModeAlnum: {3, 4, 5}, qrModeByte: {0, 4, 5}}
	for i, m := range []micro{{1, 32}, {2, 68}, {3, 112}} {
		if countBits[mode][i] == 0 {
			continue
		}
		if m.modeBits+countBits[mode][i]+dataBits <= m.capacity {
			return true
		}
	}
	return false
}

// qrEncode is segno.make(text, error="m") for a QR Code: its modules,
// true for dark, without the quiet zone.
func qrEncode(text string) ([][]byte, error) {
	mode, data, count, err := qrSegment(text)
	if err != nil {
		return nil, err
	}
	if qrMicroFits(mode, len(data)) {
		return nil, errQRUnsupported
	}
	length := func(v int) int { return 4 + qrCountBits(mode, v) + len(data) }
	version := 0
	for v := 1; v <= 40; v++ {
		if qrCapacity(v, qrLevelM) >= length(v) {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, fmt.Errorf("qr: %d characters do not fit in a QR Code", count)
	}
	// boost_error_level: the highest level that still fits this version.
	level := qrLevelM
	for _, l := range []int{qrLevelQ, qrLevelH} {
		if qrCapacity(version, l) < length(version) {
			break
		}
		level = l
	}
	capacity := qrCapacity(version, level)
	var buf bits
	buf.add(mode, 4)
	buf.add(count, qrCountBits(mode, version))
	buf = append(buf, data...)
	buf = append(buf, make(bits, min(capacity-len(buf), 4))...) // terminator
	// segno's write_padding_bits adds a whole zero byte when the stream
	// already ends on a byte boundary.
	buf = append(buf, make(bits, 8-len(buf)%8)...)
	pad := [2][]byte{{1, 1, 1, 0, 1, 1, 0, 0}, {0, 0, 0, 1, 0, 0, 0, 1}}
	for i, n := 0, capacity/8-len(buf)/8; i < n; i++ {
		buf = append(buf, pad[i%2]...)
	}
	codewords := qrFinalMessage(version, level, buf)

	size := version*4 + 17
	m := qrFunctionMatrix(size, version)
	qrPlace(m, codewords)
	fn := qrFunctionMatrix(size, version)
	fn[size-8][8] = 1
	best, bestScore := -1, int(^uint(0)>>1)
	var bestMatrix [][]byte
	for mask := range 8 {
		c := qrCopy(m)
		for i := range size {
			for j := range size {
				if fn[i][j] > 1 && qrMask(mask, i, j) {
					c[i][j] ^= 1
				}
			}
		}
		if s := qrPenalty(c); s < bestScore {
			best, bestScore, bestMatrix = mask, s, c
		}
	}
	qrFormat(bestMatrix, level, best)
	qrVersion(bestMatrix, version)
	return bestMatrix, nil
}

func qrCopy(m [][]byte) [][]byte {
	c := make([][]byte, len(m))
	for i := range m {
		c[i] = append([]byte(nil), m[i]...)
	}
	return c
}

var qrExp, qrLog [512]int

func init() {
	x := 1
	for i := range 255 {
		qrExp[i], qrExp[i+255] = x, x
		qrLog[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
}

// qrGenerator is the generator polynomial for n error codewords, as the
// logs of its coefficients after the leading one.
func qrGenerator(n int) []int {
	poly := []int{1}
	for i := range n {
		next := make([]int, len(poly)+1)
		for j, c := range poly {
			next[j] ^= c
			if c != 0 {
				next[j+1] ^= qrExp[qrLog[c]+i]
			}
		}
		poly = next
	}
	out := make([]int, n)
	for i := range n {
		out[i] = qrLog[poly[i+1]]
	}
	return out
}

// qrFinalMessage is make_final_message: the data codewords in blocks,
// their error correction, interleaved, and the remainder bits.
func qrFinalMessage(version, level int, buf bits) bits {
	var ints []int
	for i := 0; i < len(buf); i += 8 {
		v := 0
		for k := range 8 {
			v <<= 1
			if i+k < len(buf) {
				v |= int(buf[i+k])
			}
		}
		ints = append(ints, v)
	}
	var dataBlocks, ecBlocks [][]int
	pos := 0
	for _, g := range qrBlocks[version][level] {
		n := g.total - g.data
		gen := qrGenerator(n)
		for range g.blocks {
			block := append([]int(nil), ints[pos:pos+g.data]...)
			pos += g.data
			dataBlocks = append(dataBlocks, block)
			ec := append(append([]int(nil), block...), make([]int, n)...)
			for k := range block {
				if coef := ec[k]; coef != 0 {
					l := qrLog[coef]
					for j := range n {
						ec[k+j+1] ^= qrExp[l+gen[j]]
					}
				}
			}
			ecBlocks = append(ecBlocks, ec[len(block):])
		}
	}
	var out bits
	for _, blocks := range [][][]int{dataBlocks, ecBlocks} {
		longest := 0
		for _, b := range blocks {
			longest = max(longest, len(b))
		}
		for i := range longest {
			for _, b := range blocks {
				if i < len(b) {
					out.add(b[i], 8)
				}
			}
		}
	}
	remainder := 0
	switch {
	case version >= 2 && version <= 6:
		remainder = 7
	case version >= 14 && version <= 20, version >= 28 && version <= 34:
		remainder = 3
	case version >= 21 && version <= 27:
		remainder = 4
	}
	return append(out, make(bits, remainder)...)
}

var qrFinder = [9][9]byte{
	{0, 0, 0, 0, 0, 0, 0, 0, 0},
	{0, 1, 1, 1, 1, 1, 1, 1, 0},
	{0, 1, 0, 0, 0, 0, 0, 1, 0},
	{0, 1, 0, 1, 1, 1, 0, 1, 0},
	{0, 1, 0, 1, 1, 1, 0, 1, 0},
	{0, 1, 0, 1, 1, 1, 0, 1, 0},
	{0, 1, 0, 0, 0, 0, 0, 1, 0},
	{0, 1, 1, 1, 1, 1, 1, 1, 0},
	{0, 0, 0, 0, 0, 0, 0, 0, 0},
}

// qrFunctionMatrix is make_matrix with the finder and alignment
// patterns and the timing pattern: 2 marks a module free for data, the
// format and version areas are reserved as 0.
func qrFunctionMatrix(size, version int) [][]byte {
	m := make([][]byte, size)
	for i := range m {
		m[i] = make([]byte, size)
		for j := range m[i] {
			m[i][j] = 2
		}
	}
	at := func(i int) int { // a Python index, negative from the end
		if i < 0 {
			return size + i
		}
		return i
	}
	if size > 41 {
		for i := range 6 {
			m[i][size-11], m[i][size-10], m[i][size-9] = 0, 0, 0
			m[size-11][i], m[size-10][i], m[size-9][i] = 0, 0, 0
		}
	}
	for i := range 9 {
		m[i][8], m[8][i] = 0, 0
		m[at(-i)][8], m[8][at(-i)] = 0, 0
	}
	bit := byte(1)
	for i := 8; i < size-8; i++ {
		m[i][6], m[6][i] = bit, bit
		bit ^= 1
	}
	for _, corner := range [][2]int{{0, 0}, {0, size - 8}, {-8, 0}} {
		i, j := corner[0], corner[1]
		offset, sep := 0, 1
		if i == 0 {
			offset = 1
		}
		if j != 0 {
			sep = 0
		}
		for r := range 8 {
			copy(m[at(i)+r][j:j+8], qrFinder[offset+r][sep:sep+8])
		}
	}
	if version >= 2 {
		pos := qrAlignment[version-2]
		lo, hi := pos[0], pos[len(pos)-1]
		for _, x := range pos {
			for _, y := range pos {
				if (x == lo && y == lo) || (x == lo && y == hi) || (x == hi && y == lo) {
					continue
				}
				for r := range 5 {
					for c := range 5 {
						dark := r == 0 || r == 4 || c == 0 || c == 4 || (r == 2 && c == 2)
						m[x-2+r][y-2+c] = map[bool]byte{true: 1, false: 0}[dark]
					}
				}
			}
		}
	}
	return m
}

// qrPlace is add_codewords: the bit stream up and down the two-module
// columns from the right.
func qrPlace(m [][]byte, codewords bits) {
	size := len(m)
	idx := 0
	for col := size - 1; col > 0; col -= 2 {
		right := col
		if right <= 6 {
			right--
		}
		for vertical := range size {
			for z := range 2 {
				j := right - z
				upwards := (right&2 == 0) != (j < 6)
				i := vertical
				if upwards {
					i = size - 1 - vertical
				}
				if m[i][j] == 2 && idx < len(codewords) {
					m[i][j] = codewords[idx]
					idx++
				}
			}
		}
	}
}

func qrMask(mask, i, j int) bool {
	switch mask {
	case 0:
		return (i+j)&1 == 0
	case 1:
		return i&1 == 0
	case 2:
		return j%3 == 0
	case 3:
		return (i+j)%3 == 0
	case 4:
		return (i/2+j/3)&1 == 0
	case 5:
		return (i*j)&1+(i*j)%3 == 0
	case 6:
		return ((i*j)&1+(i*j)%3)&1 == 0
	}
	return (((i+j)&1)+(i*j)%3)&1 == 0
}

// qrPenalty is segno's mask_scores summed (ISO/IEC 18004 7.8.3.1, as
// segno counts it: before the format information is written).
func qrPenalty(m [][]byte) int {
	size := len(m)
	n3 := func(seq []byte) int {
		pattern := []byte{1, 0, 1, 1, 1, 0, 1}
		count := 0
		find := func(from int) int {
			for k := from; k+7 <= len(seq); k++ {
				if string(seq[k:k+7]) == string(pattern) {
					return k
				}
			}
			return -1
		}
		any := func(s []byte) bool {
			for _, b := range s {
				if b != 0 {
					return true
				}
			}
			return false
		}
		idx := find(0)
		for idx != -1 {
			offset := idx + 7
			if idx == 0 || idx == size-7 || !any(seq[max(idx-4, 0):min(idx, size)]) ||
				!any(seq[max(offset, 0):min(offset+4, size)]) {
				count += 40
			} else {
				offset = idx + 4
			}
			idx = find(offset)
		}
		return count
	}
	score, dark := 0, 0
	column := make([]byte, size)
	var lastRow []byte
	for i := range size {
		row := m[i]
		rowPrev, colPrev := -1, -1
		rowRun, colRun := 0, 0
		for j := range size {
			cur, col := int(row[j]), int(m[j][i])
			column[j] = m[j][i]
			dark += cur
			if cur == rowPrev {
				rowRun++
			} else {
				if rowRun >= 5 {
					score += rowRun - 2
				}
				rowRun = 1
			}
			if col == colPrev {
				colRun++
			} else {
				if colRun >= 5 {
					score += colRun - 2
				}
				colRun = 1
			}
			if lastRow != nil && j > 0 && cur == rowPrev && rowPrev == int(lastRow[j]) && int(lastRow[j]) == int(lastRow[j-1]) {
				score += 3
			}
			rowPrev, colPrev = cur, col
		}
		lastRow = row
		score += n3(row) + n3(column)
		if rowRun >= 5 {
			score += rowRun - 2
		}
		if colRun >= 5 {
			score += colRun - 2
		}
	}
	percent := float64(dark) / float64(size*size)
	d := percent*100 - 50
	if d < 0 {
		d = -d
	}
	return score + 10*int(d/5)
}

func qrFormat(m [][]byte, level, mask int) {
	size := len(m)
	info := qrFormatInfo[qrFormatLevel[level]<<3|mask]
	v, h := 0, 0
	for i := range 8 {
		vbit := byte(info >> i & 1)
		hbit := byte(info >> (14 - i) & 1)
		if i == 6 {
			v, h = v+1, 1
		}
		m[i+v][8] = vbit
		m[8][i+h] = hbit
		m[8][size-1-i] = vbit
		m[size-1-i][8] = hbit
	}
	m[size-8][8] = 1
}

func qrVersion(m [][]byte, version int) {
	if version < 7 {
		return
	}
	size := len(m)
	info := qrVersionInfo[version-7]
	for i := range 6 {
		for k := range 3 {
			bit := byte(info >> (i*3 + k) & 1)
			m[size-11+k][i] = bit
			m[i][size-11+k] = bit
		}
	}
}

// webColor is segno's _color_to_webcolor for "#RRGGBB": black and white
// by name of three digits, else lower case, three digits where they
// repeat.
func webColor(hex string) string {
	hx := strings.ToLower(hex)
	switch hx {
	case "#000000":
		return "#000"
	case "#ffffff":
		return "#fff"
	case "#ff0000":
		return "red"
	case "#d2b48c":
		return "tan"
	}
	if len(hx) == 7 && hx[1] == hx[2] && hx[3] == hx[4] && hx[5] == hx[6] {
		return "#" + hx[1:2] + hx[3:4] + hx[5:6]
	}
	return hx
}

// qrSVG is the code's SVG as segno writes it with a 4-module quiet zone
// and no XML declaration: a background rectangle and one path of the
// dark runs, row by row.
func qrSVGOf(text string, scale int, dark, light string) (template.HTML, error) {
	m, err := qrEncode(text)
	if err != nil {
		return "", err
	}
	const border = 4
	size := len(m)
	full := size + 2*border
	var path strings.Builder
	lastX, lastY := 0.0, 0.0
	n := 0
	emit := func(x1, x2 int, y float64) {
		move := "M"
		if n > 0 {
			move = "m"
		}
		dy := y - lastY
		ys := fmt.Sprint(dy)
		if dy == float64(int(dy)) {
			ys = fmt.Sprint(int(dy))
		}
		fmt.Fprintf(&path, "%s%d %sh%d", move, x1-int(lastX), ys, x2-x1)
		lastX, lastY = float64(x2), y
		n++
	}
	// utils.matrix_to_lines: the dark runs, from (border, border + .5).
	y := float64(border) + .5 - 1
	last := byte(1)
	for _, row := range m {
		x1, x2 := border, border
		y++
		for _, b := range row {
			if last != b && b == 0 {
				emit(x1, x2, y)
				x1 = x2
			}
			x2++
			if b == 0 {
				x1++
			}
			last = b
		}
		if last != 0 {
			emit(x1, x2, y)
			last = 0
		}
	}
	bg := fmt.Sprintf(`<path fill="%s" d="M0 0h%dv%dh-%dz"/>`, webColor(light), full, full, full)
	fg := fmt.Sprintf(`<path class="qrline" stroke="%s" d="%s"/>`, webColor(dark), path.String())
	paths := []string{bg, fg}
	if len(fg) < len(bg) {
		paths = []string{fg, bg}
	}
	return template.HTML(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" class="segno">`+
		`<g transform="scale(%d)">%s%s</g></svg>`+"\n", full*scale, full*scale, scale, paths[0], paths[1])), nil
}
