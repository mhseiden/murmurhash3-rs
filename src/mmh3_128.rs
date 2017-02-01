use std::default::Default;
use std::hash::Hasher;
use std::mem;

const READ_SIZE: usize = 16; // u8 * 16 == 128
const C1: u64 = 0x87c37b91114253d5u64;
const C2: u64 = 0x4cf5ad432745937fu64;

pub struct Murmur3State {
    words: (u64, u64),
    consumed: usize,
    xblock: Vec<u8>,
    seed: u64,
}

impl Murmur3State {
    pub fn new(seed: u64) -> Self {
        Murmur3State {
            words: (seed, seed),
            consumed: 0,
            xblock: Vec::with_capacity(READ_SIZE),
            seed: seed,
        }
    }
    pub fn clear(&mut self) {
        self.words = (self.seed, self.seed);
        self.consumed = 0;
        self.xblock.clear();
    }
}

impl Hasher for Murmur3State {
    fn write(&mut self, bytes: &[u8]) {
        murmurhash3_x64_128_write(self, bytes);
    }
    fn finish(&self) -> u64 {
        murmurhash3_x64_128_finalize(self).0
    }
}

impl Default for Murmur3State {
    fn default() -> Self {
        Murmur3State::new(0x85ebca6bc2b2ae35u64)
    }
}

#[inline(always)]
fn murmurhash3_x64_128_write(state: &mut Murmur3State, mut bytes: &[u8]) {

    // if the last mix left bytes over, try to flush them here
    let missing = READ_SIZE - state.xblock.len();
    if READ_SIZE != missing {
        // we don't have enough bytes to flush, so buffer them and return
        if bytes.len() <= missing {
            state.xblock.extend_from_slice(bytes);
            return;
        } else {
            let tail = &bytes[0..missing];
            state.xblock.extend_from_slice(tail);
            assert!(READ_SIZE == state.xblock.len());
            state.words = murmurhash3_x64_128_mix(state.words, &state.xblock, 0);

            state.xblock.clear();
            state.consumed += READ_SIZE;
            bytes = &bytes[missing..];
        }
    }

    let len = bytes.len();
    let block_count = len / READ_SIZE;
    for i in 0..block_count {
        state.words = murmurhash3_x64_128_mix(state.words, bytes, i);
        state.consumed += READ_SIZE;
    }

    assert!(state.xblock.is_empty());
    state.xblock.extend_from_slice(&bytes[(block_count * READ_SIZE)..]);
}

#[inline(always)]
fn murmurhash3_x64_128_mix(words: (u64, u64), bytes: &[u8], offset: usize) -> (u64, u64) {
    let (mut h1, mut h2) = words;
    let (mut k1, mut k2) = get_128_block(bytes, offset * 2);

    k1 = k1.wrapping_mul(C1);
    k1 = k1.rotate_left(31);
    k1 = k1.wrapping_mul(C2);
    h1 ^= k1;

    h1 = h1.rotate_left(27);
    h1 = h1.wrapping_add(h2);
    h1 = h1.wrapping_mul(5);
    h1 = h1.wrapping_add(0x52dce729);

    k2 = k2.wrapping_mul(C2);
    k2 = k2.rotate_left(33);
    k2 = k2.wrapping_mul(C1);
    h2 ^= k2;

    h2 = h2.rotate_left(31);
    h2 = h2.wrapping_add(h1);
    h2 = h2.wrapping_mul(5);
    h2 = h2.wrapping_add(0x38495ab5);

    (h1, h2)
}

#[inline(always)]
fn get_128_block(bytes: &[u8], index: usize) -> (u64, u64) {
    let b64: &[u64] = unsafe { mem::transmute(bytes) };

    return (b64[index], b64[index + 1]);
}

#[inline(always)]
fn murmurhash3_x64_128_finalize(state: &Murmur3State) -> (u64, u64) {
    let bytes = &state.xblock;
    let len = bytes.len();
    let consumed = state.consumed + len;

    let (mut h1, mut h2) = state.words;
    let (mut k1, mut k2) = (0u64, 0u64);

    if len & 15 == 15 {
        k2 ^= (bytes[14] as u64) << 48;
    }
    if len & 15 >= 14 {
        k2 ^= (bytes[13] as u64) << 40;
    }
    if len & 15 >= 13 {
        k2 ^= (bytes[12] as u64) << 32;
    }
    if len & 15 >= 12 {
        k2 ^= (bytes[11] as u64) << 24;
    }
    if len & 15 >= 11 {
        k2 ^= (bytes[10] as u64) << 16;
    }
    if len & 15 >= 10 {
        k2 ^= (bytes[9] as u64) << 8;
    }
    if len & 15 >= 9 {
        k2 ^= bytes[8] as u64;
        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
    }

    if len & 15 >= 8 {
        k1 ^= (bytes[7] as u64) << 56;
    }
    if len & 15 >= 7 {
        k1 ^= (bytes[6] as u64) << 48;
    }
    if len & 15 >= 6 {
        k1 ^= (bytes[5] as u64) << 40;
    }
    if len & 15 >= 5 {
        k1 ^= (bytes[4] as u64) << 32;
    }
    if len & 15 >= 4 {
        k1 ^= (bytes[3] as u64) << 24;
    }
    if len & 15 >= 3 {
        k1 ^= (bytes[2] as u64) << 16;
    }
    if len & 15 >= 2 {
        k1 ^= (bytes[1] as u64) << 8;
    }
    if len & 15 >= 1 {
        k1 ^= bytes[0] as u64;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= consumed as u64;
    h2 ^= consumed as u64;

    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);

    (h1, h2)
}

#[inline(always)]
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccdu64);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53u64);
    k ^= k >> 33;

    return k;
}

#[cfg(test)]
mod test {

    fn murmurhash3_x64_128(bytes: &[u8], seed: u64) -> (u64, u64) {
        let mut state = super::Murmur3State {
            words: (seed, seed),
            consumed: 0,
            xblock: Vec::with_capacity(super::READ_SIZE),
        };

        super::murmurhash3_x64_128_write(&mut state, bytes);
        super::murmurhash3_x64_128_finalize(&state)
    }

    #[test]
    fn test_empty_string() {
        assert!(murmurhash3_x64_128("".as_bytes(), 0) == (0, 0));
    }

    #[test]
    fn test_tail_lengths() {
        assert!(murmurhash3_x64_128("1".as_bytes(), 0) ==
                (8213365047359667313, 10676604921780958775));
        assert!(murmurhash3_x64_128("12".as_bytes(), 0) ==
                (5355690773644049813, 9855895140584599837));
        assert!(murmurhash3_x64_128("123".as_bytes(), 0) ==
                (10978418110857903978, 4791445053355511657));
        assert!(murmurhash3_x64_128("1234".as_bytes(), 0) ==
                (619023178690193332, 3755592904005385637));
        assert!(murmurhash3_x64_128("12345".as_bytes(), 0) ==
                (2375712675693977547, 17382870096830835188));
        assert!(murmurhash3_x64_128("123456".as_bytes(), 0) ==
                (16435832985690558678, 5882968373513761278));
        assert!(murmurhash3_x64_128("1234567".as_bytes(), 0) ==
                (3232113351312417698, 4025181827808483669));
        assert!(murmurhash3_x64_128("12345678".as_bytes(), 0) ==
                (4272337174398058908, 10464973996478965079));
        assert!(murmurhash3_x64_128("123456789".as_bytes(), 0) ==
                (4360720697772133540, 11094893415607738629));
        assert!(murmurhash3_x64_128("123456789a".as_bytes(), 0) ==
                (12594836289594257748, 2662019112679848245));
        assert!(murmurhash3_x64_128("123456789ab".as_bytes(), 0) ==
                (6978636991469537545, 12243090730442643750));
        assert!(murmurhash3_x64_128("123456789abc".as_bytes(), 0) ==
                (211890993682310078, 16480638721813329343));
        assert!(murmurhash3_x64_128("123456789abcd".as_bytes(), 0) ==
                (12459781455342427559, 3193214493011213179));
        assert!(murmurhash3_x64_128("123456789abcde".as_bytes(), 0) ==
                (12538342858731408721, 9820739847336455216));
        assert!(murmurhash3_x64_128("123456789abcdef".as_bytes(), 0) ==
                (9165946068217512774, 2451472574052603025));
        assert!(murmurhash3_x64_128("123456789abcdef1".as_bytes(), 0) ==
                (9259082041050667785, 12459473952842597282));
    }

    #[test]
    fn test_large_data() {
        assert!(murmurhash3_x64_128("Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
                                     Etiam at consequat massa. Cras eleifend pellentesque ex, \
                                     at dignissim libero maximus ut. Sed eget nulla felis"
                                        .as_bytes(),
                                    0) ==
                (9455322759164802692, 17863277201603478371));
    }
}
