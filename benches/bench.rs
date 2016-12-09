#![feature(test)]
extern crate test;
extern crate rand;
extern crate murmurhash3;

use std::iter::FromIterator;
use std::hash::Hasher;

use rand::Rng;
use test::{Bencher, black_box};

fn run_bench(b: &mut Bencher, size: u64) {
    let mut data: Vec<u8> = FromIterator::from_iter((0..size).map(|_| 0u8));
    rand::thread_rng().fill_bytes(&mut data);

    b.bytes = size;
    b.iter(|| {
        black_box({
            let mut hasher = murmurhash3::Murmur3Hasher::new(0);
            hasher.write(&data);
            hasher.finish();
        });
    });
}

#[bench]
fn bench_random_1m(b: &mut Bencher) {
    run_bench(b, 1024 * 1024);
}

#[bench]
fn bench_random_256k(b: &mut Bencher) {
    run_bench(b, 256 * 1024);
}

#[bench]
fn bench_random_16b(b: &mut Bencher) {
    run_bench(b, 16);
}
