use core::panic;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

fn main() {
    challenge1_1();

    challenge1_2();

    challenge1_3();

    challenge1_4();

    challenge1_5();

    let path = Path::new("6.txt");
    let b64_str = read_from_file(path);

    for line in b64_str.lines() {
        let b64_line_bytes = b64str_to_bytes(line);
        let hex_str = u8slice_to_hexstr(&b64_line_bytes);
        println!("{:?}", &hex_str);
    }

    let str1 = "this is a test".as_bytes();
    let str2 = "wokka wokka!!!".as_bytes();

    let ham_dist = hamming_dist_of_bytes(str1, str2);
    println!("{:?}", ham_dist);
}

fn hamming_dist_of_bytes(str1: &[u8], str2: &[u8]) -> u8 {
    let mut ham_dist = 0;
    for i in 0..str1.len() {
        ham_dist += hamming_distance(str1[i], str2[i]);
    }
    ham_dist
}

fn hamming_distance(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut x = a ^ b;

    while x > 0 {
        result += x & 1;
        x >>= 1;
    }
    result
}

fn challenge1_5() {
    let plain_strings =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let repeating_key = repeating_xor_key(key, plain_strings);

    // convert to bytes and then xor the line and line_key bytes.
    let encoded_bytes: Vec<u8> = repeating_xor_encode(plain_strings, &repeating_key);

    let encoded_hexstr = u8slice_to_hexstr(&encoded_bytes);

    println!("Set 1 Challenge 5:");

    println!(
        "\tHex Str Length: {:?}\n\t{:?}",
        encoded_hexstr.len(),
        encoded_hexstr
    );
    // }
    let answer_hexstr = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    println!(
        "\tAnswer Len: {:?}\n\tAnswer:\n\t{:?}",
        answer_hexstr.len(),
        answer_hexstr
    );
}

fn repeating_xor_encode(line: &str, repeating_key: &str) -> Vec<u8> {
    let line_bytes = line.as_bytes();
    let key_bytes = repeating_key.as_bytes();

    let mut encoded_bytes = Vec::new();
    for (i, &byte) in line_bytes.iter().enumerate() {
        encoded_bytes.push(byte ^ key_bytes[i]);
    }
    encoded_bytes
}

fn u8slice_to_hexstr(u8_slice: &[u8]) -> String {
    let mut hex_bytes: Vec<char> = Vec::new();
    // for byte in string.as_bytes() {
    for byte in u8_slice {
        let (hex1, hex2) = from_u8_to_hexstr(*byte);
        hex_bytes.push(hex1);
        hex_bytes.push(hex2);
    }
    String::from_iter(hex_bytes)
}

fn repeating_xor_key(key: &str, string: &str) -> String {
    let string_len = string.len();
    let key_len = key.len();
    let mut key_str = String::new();
    for _i in 0..((string_len - string_len % key_len) / key_len) {
        key_str.push_str(key);
    }
    if string_len % key_len != 0 {
        key_str.push_str(&key[..(string_len % key_len)])
    }

    key_str
}

fn challenge1_4() {
    // Create a path to the desired file
    let path = Path::new("4.txt");
    let encoded_strings = read_from_file(path);

    let mut top_score = 0f64;
    let mut decoded_string_bytes: Vec<u8> = Vec::new();
    for (i, line) in encoded_strings.lines().enumerate() {
        let (decoded_line, score) = decode_xor_string(line);
        if i == 0 {
            top_score = score;
        } else if score > top_score {
            top_score = score;
            decoded_string_bytes = decoded_line;
        }
    }

    println!("Set 1 Challenge 4:");
    println!(
        "\t{:?}",
        String::from_iter::<Vec<char>>(decoded_string_bytes.iter().map(|&x| x as char).collect())
    )
}

fn read_from_file(path: &Path) -> String {
    let display = path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut encoded_strings = String::new();
    match file.read_to_string(&mut encoded_strings) {
        Err(why) => panic!("couldn't read {}: {}", display, why),
        Ok(_) => print!("{} read successfully\n" /*{}""*/, display /*, s*/),
    }
    encoded_strings
}

fn challenge1_3() {
    let encoded_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (decoded_bytes, _) = decode_xor_string(encoded_str);
    println!("Set 1 Challenge 3:");
    println!(
        "\t{:?}",
        String::from_iter::<Vec<char>>(decoded_bytes.iter().map(|&x| x as char).collect())
    );
}

fn decode_xor_string(encoded_str: &str) -> (Vec<u8>, f64) {
    let encoded_bytes = hexstr_to_u8vec(encoded_str);

    let (best_score, key) = get_score(&encoded_bytes);

    let encoded_bytes = hexstr_to_u8vec(encoded_str);
    let decoded_bytes = decode_single_xor_bytes(key, encoded_bytes);

    (decoded_bytes, best_score)
}

fn decode_single_xor_bytes(key: u8, encoded_bytes: Vec<u8>) -> Vec<u8> {
    let decoded_bytes: Vec<u8> = encoded_bytes.iter().map(|x| *x ^ key as u8).collect();
    decoded_bytes
}

fn get_score(encoded_bytes: &[u8]) -> (f64, u8) {
    const OCCURANCE_ENGLISH: [f64; 26] = [
        8.2389258, 1.5051398, 2.8065007, 4.2904556, 12.813865, 2.2476217, 2.0327458, 6.1476691,
        6.1476691, 0.1543474, 0.7787989, 4.0604477, 2.4271893, 6.8084376, 7.5731132, 1.9459884,
        0.0958366, 6.0397268, 6.3827211, 9.1357551, 2.7822893, 0.9866131, 2.3807842, 0.1513210,
        1.9913847, 0.0746517,
    ];

    let mut best_score = 0f64;
    let mut best_key = 0u8;
    for key in 0u8..=255u8 {
        let mut score = 0f64;
        for byte in encoded_bytes {
            let decoded_byte = *byte ^ key;

            if decoded_byte >= b'a' && decoded_byte <= b'z' {
                score += OCCURANCE_ENGLISH[(decoded_byte - b'a') as usize];
            } else if decoded_byte >= b'A' && decoded_byte <= b'Z' {
                score += OCCURANCE_ENGLISH[(decoded_byte - b'A') as usize];
            } else if decoded_byte == b' ' {
                score += 15f64;
            }
        }
        if key == 0 {
            best_score = score;
        } else if score > best_score {
            best_score = score;
            best_key = key;
        }
    }
    (best_score, best_key)
}

fn challenge1_2() {
    let hex1 = "1c0111001f010100061a024b53535009181c";
    let hex2 = "686974207468652062756c6c277320657965";

    let fixed_xor_str = xor_hex_strings(hex1, hex2);

    println!("Set 1 Challenge 2:");
    println!("\tResult: {:?}", fixed_xor_str);
    println!("\tAnswer: {:?}", "746865206b696420646f6e277420706c6179")
}

fn xor_hex_strings(hex1: &str, hex2: &str) -> String {
    let hex1_bytes = hexstr_to_u8vec(hex1);
    let hex2_bytes = hexstr_to_u8vec(hex2);

    let fixed_xor: Vec<(char, char)> = hex1_bytes
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let result = x ^ hex2_bytes[i];
            from_u8_to_hexstr(result)
        })
        .collect();

    let fixed_xor_vec: Vec<Vec<char>> = fixed_xor.into_iter().map(|x| vec![x.0, x.1]).collect();
    let fixed_xor_str: String =
        String::from_iter::<Vec<char>>(fixed_xor_vec.into_iter().flatten().collect());
    fixed_xor_str
}

fn challenge1_1() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let b64_str = hex_to_b64(hex);
    println!("Set 1 Challenge 1:");
    println!("\tResult: {:?}", b64_str);
    println!("\tAnswer: {:?}", b64);
}

fn hex_to_b64(hex: &str) -> String {
    let hsize = hex.len();

    let mut hex_string = hex.to_string();
    if hsize % 2 != 0 {
        hex_string.insert(0, '0');
    }

    let hex_to_int = hexstr_to_u8vec(&hex_string);

    bytes_to_b64str(&hex_to_int)
}

fn b64str_to_bytes(b64str: &str) -> Vec<u8> {
    let mut b64_values: Vec<u8> = Vec::new();
    let mut u8_values: Vec<u8> = Vec::new();
    b64str.as_bytes().iter().for_each(|b| {
        let value: u8 = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62u8,
            b'/' => 63u8,
            b'=' => 0u8,
            _ => panic!("AHHHHH"),
        };
        b64_values.push(value);
    });
    b64_values.chunks(4).for_each(|x| {
        let mut value: u32 = (x[0] as u32) << 18;
        value |= (x[1] as u32) << 12;
        value |= (x[2] as u32) << 6;
        value |= x[3] as u32;
        for i in 0..3 {
            let byte = (value >> (16 - i * 8)) & 0xFF;
            u8_values.push(byte as u8);
        }
    });
    u8_values
}

fn bytes_to_b64str(hex_to_int: &[u8]) -> String {
    const BASE64_ALPHABET: [char; 64] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    ];

    let mut b64_int24 = Vec::new();

    hex_to_int.chunks(3).for_each(|x| {
        let mut value = (x[0] as u32) << 16;
        value |= (x[1] as u32) << 8;
        value |= x[2] as u32;
        b64_int24.push(value);
    });

    let b64_chars: Vec<Vec<char>> = b64_int24
        .into_iter()
        .map(|x| -> Vec<char> {
            let mut result = Vec::new();
            for i in 0..4 {
                let idx = (x >> (18 - i * 6)) & 0x3F;
                result.push(BASE64_ALPHABET[idx as usize]);
            }
            result
        })
        .collect();
    let b64_str: String = String::from_iter::<Vec<char>>(b64_chars.into_iter().flatten().collect());
    b64_str
}

fn hexstr_to_u8vec(hex_string: &str) -> Vec<u8> {
    let hex_to_int: Vec<u8> = hex_string
        .as_bytes()
        .chunks(2)
        .map(|x| -> u8 { from_hexstr_to_u8(x[0] as char) * 16 + from_hexstr_to_u8(x[1] as char) })
        .collect();
    hex_to_int
}

fn from_hexstr_to_u8(hex_char: char) -> u8 {
    let hexval: u8 = match hex_char {
        '0'..='9' => hex_char as u8 - b'0',
        'a'..='f' => hex_char as u8 - b'a' + 10,
        'A'..='F' => hex_char as u8 - b'A' + 10,
        _ => panic!("Invalid hex character"),
    };
    hexval
}

fn from_u8_to_hexstr(byte: u8) -> (char, char) {
    const HEX_ALPHABET: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    let byte_mod = byte % 16;
    let sixteen_place = (byte - byte_mod) / 16;
    let zero_place = byte_mod;

    let hexstr1 = HEX_ALPHABET[sixteen_place as usize];
    // let hexstr1 = match sixteen_place {
    //     0..=9 => (b'0' + sixteen_place) as char,
    //     10..=15 => (b'a' + sixteen_place - 10) as char,
    //     _ => panic!("Invalid digit"),
    // };

    let hexstr2 = HEX_ALPHABET[zero_place as usize];
    // let hexstr2 = match zero_place {
    //     0..=9 => (b'0' + zero_place) as char,
    //     10..=15 => (b'a' + zero_place - 10) as char,
    //     _ => panic!("Invalid digit"),
    // };

    (hexstr1, hexstr2)
}
